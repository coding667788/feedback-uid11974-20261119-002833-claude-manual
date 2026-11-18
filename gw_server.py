#!/usr/bin/env python3
"""本地 API 身份认证网关 HTTP 服务进程(可启动任意多个实例共享同一 SQLite 库)。

一致性核心:密钥/身份状态检查、签名验证、时间窗检查、nonce 占用、
increment 业务写入、审计记录, 全部在同一个 BEGIN IMMEDIATE 事务中提交。
撤销/禁用一旦提交, 之后进入事务的请求必然读到新状态并失败。
"""
from __future__ import annotations

import argparse
import json
import os
import re
import sqlite3
import sys
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import gw_db
import gw_protocol as P

# 受保护路由: (方法, 路径部分) -> 业务动作。其余目标一律 404 且不占用 nonce。
ROUTES = {
    ('POST', '/v1/counter/increment'): 'increment',
    ('GET', '/v1/counter'): 'query',
}

_CL_RE = re.compile(r'^(0|[1-9][0-9]*)$')


class HttpError(Exception):
    def __init__(self, status, reason):
        super().__init__(reason)
        self.status = status
        self.reason = reason


class Clock:
    """可注入时钟; 返回值保证非递减。"""

    def __init__(self, path=None):
        self.path = path
        self._last = 0.0
        self._lock = threading.Lock()

    def now(self):
        t = None
        if self.path:
            try:
                with open(self.path, 'r', encoding='ascii') as f:
                    t = float(f.read().strip())
            except (OSError, ValueError):
                t = None
        if t is None:
            t = time.time()
        with self._lock:
            if t < self._last:
                t = self._last          # 非递减: 拒绝回拨
            else:
                self._last = t
        return t


class GatewayServer(ThreadingHTTPServer):
    daemon_threads = True

    def __init__(self, addr, db_path, clock_file=None, fault_point=None, pre_tx_delay=0.0):
        super().__init__(addr, Handler)
        self.db_path = db_path
        self.clock = Clock(clock_file)
        self.fault_point = fault_point
        self.pre_tx_delay = pre_tx_delay
        self._fault_fired = False
        self._fault_lock = threading.Lock()

    def maybe_fault(self, point):
        """故障注入(仅测试): 在指定点真实终止本进程, 模拟崩溃。"""
        if self.fault_point != point:
            return
        with self._fault_lock:
            if self._fault_fired:
                return
            self._fault_fired = True
        sys.stderr.write('[gw] FAULT injected at %s, killing self\n' % point)
        sys.stderr.flush()
        os._exit(3)


class Handler(BaseHTTPRequestHandler):
    protocol_version = 'HTTP/1.1'
    server_version = 'LocalGW/1.0'

    def log_message(self, fmt, *args):
        # 只记录请求行与状态, 绝不记录签名头 / 密钥。
        sys.stderr.write('[gw] %s %s\n' % (self.address_string(), fmt % args))

    def do_GET(self):
        self._handle()

    def do_POST(self):
        self._handle()

    # ---------- 请求处理 ----------

    def _handle(self):
        try:
            if self.command == 'GET' and self.path == '/healthz':
                return self._reply(200, {'status': 'ok'})
            try:
                body = self._read_body()
                f = self._auth_fields()
                target = P.validate_target(self.path)
            except HttpError as e:
                return self._reply(e.status, {'error': e.reason})
            except P.ProtocolError as e:
                return self._reply(400, {'error': e.reason})

            # 实际请求体哈希必须与声明一致(在占用 nonce 之前)。
            if P.body_sha256_hex(body) != f['body_sha256']:
                return self._reply(401, {'error': 'body_sha256 mismatch'})

            # 越权/未知目标: 拒绝且不占用 nonce。
            path_part = target.split('?', 1)[0]
            action = ROUTES.get((self.command, path_part))
            if action is None:
                return self._reply(404, {'error': 'unknown target'})

            now = int(self.server.clock.now())
            if self.server.pre_tx_delay > 0:
                time.sleep(self.server.pre_tx_delay)   # 测试用: 拉大撤销竞态窗口
            return self._tx(f, target, action, now)
        except (BrokenPipeError, ConnectionResetError):
            pass
        except Exception as e:  # noqa: BLE001 - 兜底, 避免悬挂连接
            sys.stderr.write('[gw] internal error: %r\n' % (e,))
            try:
                self._reply(500, {'error': 'internal'})
            except Exception:
                pass

    def _tx(self, f, target, action, now):
        conn = gw_db.connect(self.server.db_path)
        try:
            conn.execute('BEGIN IMMEDIATE')
            row = conn.execute(
                'SELECT k.secret, k.status, i.id, i.tenant, i.name, i.status '
                'FROM keys k JOIN identities i ON i.id = k.identity_id '
                'WHERE k.key_id = ?', (f['key_id'],)).fetchone()
            if row is None:
                return self._deny(conn, now, f, None, action, target, 'unknown_key', 401)
            secret, kstatus, iid, tenant, iname, istatus = row
            # 状态在事务内读取: 撤销/禁用一旦提交, 此处必然看到。
            if kstatus != 'active':
                return self._deny(conn, now, f, row, action, target, 'key_not_active', 401)
            if istatus != 'active':
                return self._deny(conn, now, f, row, action, target, 'identity_disabled', 401)
            if not P.verify_hex(secret, f['signature'], self.command, target,
                                f['timestamp'], f['nonce'], f['body_sha256']):
                return self._deny(conn, now, f, row, action, target, 'bad_signature', 401)
            if abs(now - f['timestamp']) > P.SKEW_SECONDS:
                return self._deny(conn, now, f, row, action, target,
                                  'timestamp_out_of_window', 401)

            # 清理已完全过期(窗口关闭)的 nonce; 窗口内的一律保留。
            conn.execute('DELETE FROM nonces WHERE expires_at < ?', (now,))
            try:
                conn.execute(
                    'INSERT INTO nonces(identity_id, nonce, req_ts, expires_at) '
                    'VALUES (?,?,?,?)',
                    (iid, f['nonce'], f['timestamp'], f['timestamp'] + P.SKEW_SECONDS))
            except sqlite3.IntegrityError:
                conn.rollback()
                conn.execute('BEGIN IMMEDIATE')
                self._audit(conn, now, f, row, action, target, 'replay')
                conn.commit()
                return self._reply(409, {'error': 'nonce already used'})
            self.server.maybe_fault('after_nonce_insert')

            if action == 'increment':
                conn.execute(
                    'INSERT INTO counters(identity_id, value) VALUES (?, 1) '
                    'ON CONFLICT(identity_id) DO UPDATE SET value = value + 1', (iid,))
            r = conn.execute('SELECT value FROM counters WHERE identity_id = ?',
                             (iid,)).fetchone()
            value = r[0] if r else 0
            self.server.maybe_fault('after_increment')

            self._audit(conn, now, f, row, action, target, 'success')
            conn.commit()
            self.server.maybe_fault('after_commit')
            return self._reply(200, {'tenant': tenant, 'identity': iname,
                                     'action': action, 'counter': value})
        except sqlite3.Error as e:
            sys.stderr.write('[gw] db error: %r\n' % (e,))
            try:
                conn.rollback()
            except sqlite3.Error:
                pass
            return self._reply(500, {'error': 'internal'})
        finally:
            conn.close()

    # ---------- 解析与校验 ----------

    def _read_body(self):
        if self.headers.get_all('Transfer-Encoding'):
            raise HttpError(400, 'transfer-encoding not supported')
        cls = self.headers.get_all('Content-Length')
        if not cls:
            if self.command == 'POST':
                raise HttpError(411, 'content-length required')
            return b''
        if len(cls) != 1:
            raise HttpError(400, 'duplicate content-length')
        raw = cls[0]
        if not _CL_RE.match(raw):
            raise HttpError(400, 'bad content-length')
        n = int(raw)
        if n > P.MAX_BODY_BYTES:
            self.close_connection = True   # 未读 body, 直接断开避免粘包
            raise HttpError(413, 'body too large (>1MiB)')
        data = self.rfile.read(n)
        if len(data) != n:
            raise HttpError(400, 'truncated body')
        return data

    def _auth_fields(self):
        raw = {}
        for name in P.AUTH_HEADERS:
            vals = self.headers.get_all(name)
            if vals is None:
                raise HttpError(400, 'missing header ' + name)
            if len(vals) != 1:
                raise HttpError(400, 'duplicate header ' + name)
            raw[name] = vals[0]
        return {
            'key_id': P.validate_key_id(raw[P.H_KEY_ID]),
            'timestamp': P.validate_timestamp(raw[P.H_TIMESTAMP]),
            'nonce': P.validate_nonce(raw[P.H_NONCE]),
            'body_sha256': P.validate_body_sha256(raw[P.H_BODY_SHA256]),
            'signature': P.validate_signature(raw[P.H_SIGNATURE]),
        }

    # ---------- 响应与审计 ----------

    def _audit(self, conn, now, f, row, action, target, result):
        if row is not None:
            _, _, iid, tenant, iname, _ = row
        else:
            iid, tenant, iname = None, '', ''
        conn.execute(
            'INSERT INTO audit(server_ts, tenant, identity, identity_id, key_id, '
            'nonce, action, result, target) VALUES (?,?,?,?,?,?,?,?,?)',
            (now, tenant, iname, iid, f['key_id'], f['nonce'], action, result, target))

    def _deny(self, conn, now, f, row, action, target, result, status):
        self._audit(conn, now, f, row, action, target, result)
        conn.commit()
        return self._reply(status, {'error': result})

    def _reply(self, status, obj):
        data = json.dumps(obj, ensure_ascii=False).encode('utf-8')
        self.send_response(status)
        self.send_header('Content-Type', 'application/json')
        self.send_header('Content-Length', str(len(data)))
        self.end_headers()
        self.wfile.write(data)


def main():
    ap = argparse.ArgumentParser(description='本地 API 身份认证网关')
    ap.add_argument('--db', required=True, help='SQLite 数据库文件路径')
    ap.add_argument('--host', default='127.0.0.1')
    ap.add_argument('--port', type=int, required=True)
    ap.add_argument('--clock-file', default=None,
                    help='可注入时钟文件(内容为 unix 秒), 仅测试用')
    ap.add_argument('--fault-point',
                    choices=['after_nonce_insert', 'after_increment', 'after_commit'],
                    default=None, help='故障注入点(仅测试): 到达后 os._exit 自杀')
    ap.add_argument('--pre-tx-delay', type=float, default=0.0,
                    help='进入事务前延迟秒数(仅测试用)')
    a = ap.parse_args()
    srv = GatewayServer((a.host, a.port), a.db, a.clock_file,
                        a.fault_point, a.pre_tx_delay)
    sys.stderr.write('[gw] listening on %s:%d db=%s\n' % (a.host, a.port, a.db))
    sys.stderr.flush()
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        pass


if __name__ == '__main__':
    main()
