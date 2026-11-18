#!/usr/bin/env python3
"""端到端测试: 真实 HTTP 请求 + 多进程网关 + 真实进程终止,
最终用计数器与审计记录核验。运行: python -m unittest test_gateway -v
"""
from __future__ import annotations

import hashlib
import http.client
import json
import os
import secrets
import shutil
import socket
import sqlite3
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from concurrent.futures import ThreadPoolExecutor

ROOT = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, ROOT)

import gw_protocol as P  # noqa: E402

SERVER = os.path.join(ROOT, 'gw_server.py')
KEYMGR = os.path.join(ROOT, 'gw_keymgr.py')
CLIENT = os.path.join(ROOT, 'gw_client.py')


# ---------------- 测试辅助 ----------------

def free_port():
    s = socket.socket()
    s.bind(('127.0.0.1', 0))
    p = s.getsockname()[1]
    s.close()
    return p


def keymgr(db, *args):
    r = subprocess.run([sys.executable, KEYMGR, '--db', db, *args],
                       capture_output=True, text=True, timeout=60)
    if r.returncode != 0:
        raise RuntimeError('keymgr %s failed: %s' % (args, r.stderr))
    return r.stdout


def add_identity(db, tenant, name, outdir):
    out = os.path.join(outdir, 'id-%s-%s-%s.json' % (tenant, name, secrets.token_hex(3)))
    keymgr(db, 'identity-add', '--tenant', tenant, '--name', name, '--out', out)
    with open(out, encoding='utf-8') as f:
        d = json.load(f)
    return (d['key_id'], d['secret_hex'])


def key_new(db, identity, outdir):
    out = os.path.join(outdir, 'keynew-%s.json' % secrets.token_hex(4))
    keymgr(db, 'key-new', '--identity', identity, '--out', out)
    with open(out, encoding='utf-8') as f:
        d = json.load(f)
    return (d['key_id'], d['secret_hex'])


def raw_request(port, method, target, headers, body=b''):
    """最底层 HTTP 请求, 支持重复头与原始 request-target。"""
    conn = http.client.HTTPConnection('127.0.0.1', port, timeout=15)
    conn.putrequest(method, target, skip_accept_encoding=True)
    for k, v in headers:
        conn.putheader(k, v)
    if body or method == 'POST':
        conn.putheader('Content-Length', str(len(body)))
    conn.endheaders(body)
    resp = conn.getresponse()
    data = resp.read()
    status = resp.status
    conn.close()
    return status, data


def signed_headers(key, method, target, body=b'', ts=None, nonce=None,
                   sig=None, bsha=None):
    key_id, secret_hex = key
    ts = int(time.time()) if ts is None else ts
    nonce = nonce or secrets.token_hex(16)
    bsha = bsha or hashlib.sha256(body).hexdigest()
    sig = sig or P.sign_hex(bytes.fromhex(secret_hex), method, target, ts, nonce, bsha)
    return [(P.H_KEY_ID, key_id), (P.H_TIMESTAMP, str(ts)), (P.H_NONCE, nonce),
            (P.H_BODY_SHA256, bsha), (P.H_SIGNATURE, sig)]


def call(port, method, target, key, body=b'', **kw):
    return raw_request(port, method, target,
                       signed_headers(key, method, target, body, **kw), body)


class Server:
    def __init__(self, db, port, extra=(), logdir=None):
        self.db, self.port = db, port
        logpath = os.path.join(logdir or tempfile.gettempdir(),
                               'gw-%d.log' % port)
        self._log = open(logpath, 'ab')
        self.proc = subprocess.Popen(
            [sys.executable, SERVER, '--db', db, '--port', str(port), *extra],
            stdout=self._log, stderr=self._log)
        self._wait_ready()

    def _wait_ready(self, timeout=20):
        deadline = time.time() + timeout
        while time.time() < deadline:
            if self.proc.poll() is not None:
                raise RuntimeError('gateway exited early rc=%s' % self.proc.returncode)
            try:
                s, _ = raw_request(self.port, 'GET', '/healthz', [])
                if s == 200:
                    return
            except OSError:
                time.sleep(0.1)
        raise RuntimeError('gateway not ready on %d' % self.port)

    def stop(self):
        if self.proc.poll() is None:
            self.proc.terminate()
            try:
                self.proc.wait(10)
            except subprocess.TimeoutExpired:
                self.proc.kill()
                self.proc.wait(5)
        self._log.close()


def db_rows(db, sql, args=()):
    conn = sqlite3.connect(db, timeout=30)
    try:
        return conn.execute(sql, args).fetchall()
    finally:
        conn.close()


# ---------------- 主集群: 4 进程共享库 ----------------

class TestMainGateway(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.mkdtemp(prefix='gwtest-')
        cls.db = os.path.join(cls.tmp, 'gw.db')
        seed_out = os.path.join(cls.tmp, 'seed.json')
        keymgr(cls.db, 'seed', '--out', seed_out)
        with open(seed_out, encoding='utf-8') as f:
            seed = json.load(f)
        cls.alpha = (seed['t_alpha:svc']['key_id'], seed['t_alpha:svc']['secret_hex'])
        cls.beta = (seed['t_beta:svc']['key_id'], seed['t_beta:svc']['secret_hex'])
        cls.ports = [free_port() for _ in range(4)]
        cls.servers = [Server(cls.db, p, logdir=cls.tmp) for p in cls.ports]

    @classmethod
    def tearDownClass(cls):
        for s in cls.servers:
            s.stop()
        shutil.rmtree(cls.tmp, ignore_errors=True)

    def test_raw_query_string_verbatim(self):
        key, port = self.alpha, self.ports[0]
        # 原始查询串原样签名原样发送 -> 通过
        s, b = call(port, 'POST', '/v1/counter/increment?b=2&a=1', key)
        self.assertEqual(s, 200, b)
        # 签名串与发送串参数顺序不同 -> 拒绝(不排序/不归一化)
        h = signed_headers(key, 'POST', '/v1/counter/increment?a=1&b=2')
        s, b = raw_request(port, 'POST', '/v1/counter/increment?b=2&a=1', h)
        self.assertEqual(s, 401, b)
        # %41 与 A 不等价: 按 %41 签名发送 -> 通过
        s, b = call(port, 'POST', '/v1/counter/increment?x=%41', key)
        self.assertEqual(s, 200, b)
        # 按 A 签名却发送 %41 -> 拒绝(不先解码)
        h = signed_headers(key, 'POST', '/v1/counter/increment?x=A')
        s, b = raw_request(port, 'POST', '/v1/counter/increment?x=%41', h)
        self.assertEqual(s, 401, b)

    def test_body_tampered(self):
        port = self.ports[1]
        good, bad = b'{"amount":1}', b'{"amount":2}'
        h = signed_headers(self.alpha, 'POST', '/v1/counter/increment', good)
        s, b = raw_request(port, 'POST', '/v1/counter/increment', h, bad)
        self.assertEqual(s, 401, b)
        # body 哈希不匹配不占用 nonce: 同 nonce 发送正确 body 成功
        nonce = secrets.token_hex(16)
        h = signed_headers(self.alpha, 'POST', '/v1/counter/increment', good,
                           nonce=nonce)
        s, b = raw_request(port, 'POST', '/v1/counter/increment', h, bad)
        self.assertEqual(s, 401, b)
        h = signed_headers(self.alpha, 'POST', '/v1/counter/increment', good,
                           nonce=nonce)
        s, b = raw_request(port, 'POST', '/v1/counter/increment', h, good)
        self.assertEqual(s, 200, b)

    def test_duplicate_auth_header(self):
        h = signed_headers(self.alpha, 'POST', '/v1/counter/increment')
        h.append((P.H_NONCE, secrets.token_hex(16)))   # 重复 X-Nonce
        s, b = raw_request(self.ports[0], 'POST', '/v1/counter/increment', h)
        self.assertEqual(s, 400, b)

    def test_malformed_fields_rejected(self):
        port = self.ports[2]
        base = dict(signed_headers(self.alpha, 'POST', '/v1/counter/increment'))

        def with_field(name, value):
            h = list(base.items())
            h = [(k, v) for k, v in h if k != name] + [(name, value)]
            return raw_request(port, 'POST', '/v1/counter/increment', h)[0]

        self.assertEqual(with_field(P.H_TIMESTAMP, '007'), 400)      # 前导零
        self.assertEqual(with_field(P.H_TIMESTAMP, '12a'), 400)      # 非数字
        self.assertEqual(with_field(P.H_TIMESTAMP, ''), 400)         # 空
        self.assertEqual(with_field(P.H_TIMESTAMP, '1' * 30), 400)   # 超长
        self.assertEqual(with_field(P.H_NONCE, 'abcd'), 400)         # 太短
        self.assertEqual(with_field(P.H_NONCE, 'A' * 32), 400)       # 非小写
        self.assertEqual(with_field(P.H_SIGNATURE, 'F' * 64), 400)   # 非小写
        self.assertEqual(with_field(P.H_BODY_SHA256, 'x' * 64), 400)
        self.assertEqual(with_field(P.H_KEY_ID, 'bad id'), 400)      # 含空格
        # 缺头
        h = [(k, v) for k, v in base.items() if k != P.H_NONCE]
        s, _ = raw_request(port, 'POST', '/v1/counter/increment', h)
        self.assertEqual(s, 400)

    def test_body_limit_1mib(self):
        # 声明超限的 Content-Length(不实际发送 body), 网关必须仅凭头部拒绝
        body = b'x' * (P.MAX_BODY_BYTES + 1)
        h = signed_headers(self.alpha, 'POST', '/v1/counter/increment', body)
        conn = http.client.HTTPConnection('127.0.0.1', self.ports[3], timeout=15)
        conn.putrequest('POST', '/v1/counter/increment', skip_accept_encoding=True)
        for k, v in h:
            conn.putheader(k, v)
        conn.putheader('Content-Length', str(len(body)))
        conn.endheaders()
        resp = conn.getresponse()
        resp.read()
        self.assertEqual(resp.status, 413)
        conn.close()

    def test_unknown_target_does_not_consume_nonce(self):
        port = self.ports[0]
        nonce = secrets.token_hex(16)
        s, b = call(port, 'POST', '/v1/admin', self.alpha, nonce=nonce)
        self.assertEqual(s, 404, b)
        # 同一 nonce 用于合法目标仍可用 -> 越权目标未占用 nonce
        s, b = call(port, 'POST', '/v1/counter/increment', self.alpha, nonce=nonce)
        self.assertEqual(s, 200, b)

    def test_retry_after_bad_signature(self):
        port = self.ports[1]
        nonce = secrets.token_hex(16)
        # 错误签名 -> 401, 不得占用 nonce
        s, b = call(port, 'POST', '/v1/counter/increment', self.alpha,
                    nonce=nonce, sig='0' * 64)
        self.assertEqual(s, 401, b)
        # 合法重试(同 nonce, 正确签名) -> 成功
        s, b = call(port, 'POST', '/v1/counter/increment', self.alpha, nonce=nonce)
        self.assertEqual(s, 200, b)
        # 再次重放 -> 已消费
        s, b = call(port, 'POST', '/v1/counter/increment', self.alpha, nonce=nonce)
        self.assertEqual(s, 409, b)

    def test_old_new_keys_share_nonce(self):
        k1 = add_identity(self.db, 't_alpha', 'rotation', self.tmp)
        k2 = key_new(self.db, 't_alpha:rotation', self.tmp)
        nonce = secrets.token_hex(16)
        s, b = call(self.ports[0], 'POST', '/v1/counter/increment', k1, nonce=nonce)
        self.assertEqual(s, 200, b)
        # 同一 nonce 换用新密钥签名: 仍只能消费一次
        s, b = call(self.ports[1], 'POST', '/v1/counter/increment', k2, nonce=nonce)
        self.assertEqual(s, 409, b)
        # 第三把密钥不被允许(最多新旧两把)
        r = subprocess.run([sys.executable, KEYMGR, '--db', self.db, 'key-new',
                            '--identity', 't_alpha:rotation'],
                           capture_output=True, text=True, timeout=60)
        self.assertNotEqual(r.returncode, 0)

    def test_cross_tenant_same_name_identity(self):
        nonce = secrets.token_hex(16)
        s, b = call(self.ports[0], 'POST', '/v1/counter/increment', self.alpha,
                    nonce=nonce)
        self.assertEqual(s, 200, b)
        # 跨租户同名身份: nonce 唯一性按 (租户,身份) 隔离, 互不影响
        s, b = call(self.ports[1], 'POST', '/v1/counter/increment', self.beta,
                    nonce=nonce)
        self.assertEqual(s, 200, b)
        s, b = call(self.ports[2], 'GET', '/v1/counter', self.beta)
        self.assertEqual(json.loads(b)['counter'], 1)

    def test_revoke_and_disable_interleaved(self):
        k = add_identity(self.db, 't_alpha', 'revme', self.tmp)
        dport = free_port()
        srv = Server(self.db, dport, extra=('--pre-tx-delay', '1.0'), logdir=self.tmp)
        try:
            result = {}

            def worker():
                result['r'] = call(dport, 'POST', '/v1/counter/increment', k)

            t = threading.Thread(target=worker)
            t.start()
            time.sleep(0.3)   # 请求已到达网关, 尚在事务前延迟中
            keymgr(self.db, 'key-revoke', '--key-id', k[0])   # 撤销先提交
            t.join(15)
            self.assertFalse(t.is_alive())
            s, b = result['r']
            # 尚未提交的旧密钥请求重新检查状态后必须失败
            self.assertEqual(s, 401, b)
            # 撤销返回后新开始的请求也必须拒绝
            s, b = call(self.ports[0], 'POST', '/v1/counter/increment', k)
            self.assertEqual(s, 401, b)
            # 启用新密钥后可用
            k2 = key_new(self.db, 't_alpha:revme', self.tmp)
            s, b = call(self.ports[0], 'POST', '/v1/counter/increment', k2)
            self.assertEqual(s, 200, b)
            # 禁用整个身份 -> 新密钥也拒绝; 重新启用后恢复
            keymgr(self.db, 'identity-disable', '--identity', 't_alpha:revme')
            s, b = call(self.ports[0], 'POST', '/v1/counter/increment', k2)
            self.assertEqual(s, 401, b)
            keymgr(self.db, 'identity-enable', '--identity', 't_alpha:revme')
            s, b = call(self.ports[0], 'POST', '/v1/counter/increment', k2)
            self.assertEqual(s, 200, b)
        finally:
            srv.stop()

    def test_concurrent_increments_four_processes(self):
        k = add_identity(self.db, 't_alpha', 'conc', self.tmp)
        n_threads, n_per = 8, 25

        def work(i):
            ok = 0
            for j in range(n_per):
                port = self.ports[(i + j) % len(self.ports)]
                s, _ = call(port, 'POST', '/v1/counter/increment', k)
                if s == 200:
                    ok += 1
            return ok

        with ThreadPoolExecutor(n_threads) as ex:
            total = sum(ex.map(work, range(n_threads)))
        expect = n_threads * n_per
        self.assertEqual(total, expect)

        iid = db_rows(self.db,
                      'SELECT id FROM identities WHERE tenant=? AND name=?',
                      ('t_alpha', 'conc'))[0][0]
        # 计数器 == 成功数 == 审计成功数 == nonce 占用数
        self.assertEqual(db_rows(self.db,
                                 'SELECT value FROM counters WHERE identity_id=?',
                                 (iid,))[0][0], expect)
        self.assertEqual(db_rows(self.db,
                                 "SELECT COUNT(*) FROM audit WHERE identity_id=? "
                                 "AND result='success' AND action='increment'",
                                 (iid,))[0][0], expect)
        self.assertEqual(db_rows(self.db,
                                 'SELECT COUNT(*) FROM nonces WHERE identity_id=?',
                                 (iid,))[0][0], expect)
        # 不存在 "nonce 占了但业务没做" 的已提交状态
        orphan = db_rows(self.db,
                         'SELECT COUNT(*) FROM nonces n WHERE NOT EXISTS '
                         "(SELECT 1 FROM audit a WHERE a.identity_id=n.identity_id "
                         "AND a.nonce=n.nonce AND a.result='success')")[0][0]
        self.assertEqual(orphan, 0)
        # 查询接口核验
        s, b = call(self.ports[3], 'GET', '/v1/counter', k)
        self.assertEqual(json.loads(b)['counter'], expect)

    def test_client_cli(self):
        r = subprocess.run(
            [sys.executable, CLIENT, '--url',
             'http://127.0.0.1:%d/v1/counter/increment' % self.ports[0],
             '--method', 'POST', '--key-id', self.alpha[0],
             '--secret-hex', self.alpha[1]],
            capture_output=True, text=True, timeout=30)
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertIn('HTTP 200', r.stdout)


# ---------------- 时间窗边界(注入时钟) ----------------

class TestExpiryBoundary(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.mkdtemp(prefix='gwclock-')
        cls.db = os.path.join(cls.tmp, 'gw.db')
        keymgr(cls.db, 'init')
        cls.key = add_identity(cls.db, 't_alpha', 'clk', cls.tmp)
        cls.T = 1_800_000_000
        cls.clock_file = os.path.join(cls.tmp, 'clock.txt')
        with open(cls.clock_file, 'w') as f:
            f.write(str(cls.T))
        cls.port = free_port()
        cls.srv = Server(cls.db, cls.port,
                         extra=('--clock-file', cls.clock_file), logdir=cls.tmp)

    @classmethod
    def tearDownClass(cls):
        cls.srv.stop()
        shutil.rmtree(cls.tmp, ignore_errors=True)

    def test_window_edges(self):
        T = self.T
        for ts, expect in ((T - 60, 200), (T - 61, 401),
                           (T + 60, 200), (T + 61, 401)):
            with self.subTest(ts=ts):
                s, b = call(self.port, 'POST', '/v1/counter/increment',
                            self.key, ts=ts)
                self.assertEqual(s, expect, b)
        s, b = call(self.port, 'GET', '/v1/counter', self.key, ts=T)
        self.assertEqual(json.loads(b)['counter'], 2)   # 只有两笔落在窗口内


# ---------------- 崩溃恢复: 真实终止进程后重放 ----------------

class TestCrashRecovery(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.mkdtemp(prefix='gwcrash-')
        cls.db = os.path.join(cls.tmp, 'gw.db')
        keymgr(cls.db, 'init')

    @classmethod
    def tearDownClass(cls):
        shutil.rmtree(cls.tmp, ignore_errors=True)

    def test_crash_points_replay(self):
        cases = [('after_nonce_insert', 200),   # 未提交 -> 回滚 -> 重放成功
                 ('after_increment', 200),      # 未提交 -> 回滚 -> 重放成功
                 ('after_commit', 409)]         # 已提交 -> 重放判重
        for point, expect_replay in cases:
            with self.subTest(point=point):
                k = add_identity(self.db, 't_alpha', 'crash_' + point, self.tmp)
                port = free_port()
                srv = Server(self.db, port, extra=('--fault-point', point),
                             logdir=self.tmp)
                ts, nonce = int(time.time()), secrets.token_hex(16)
                h = signed_headers(k, 'POST', '/v1/counter/increment',
                                   ts=ts, nonce=nonce)
                with self.assertRaises((OSError, http.client.HTTPException)):
                    raw_request(port, 'POST', '/v1/counter/increment', h)
                srv.proc.wait(15)          # 进程确已真实终止
                self.assertIsNotNone(srv.proc.returncode)
                srv.stop()
                # 重启并用原请求重放
                srv2 = Server(self.db, port, logdir=self.tmp)
                try:
                    s, b = raw_request(port, 'POST', '/v1/counter/increment', h)
                    self.assertEqual(s, expect_replay, b)
                    # 计数最多增加一次
                    s, b = call(port, 'GET', '/v1/counter', k)
                    self.assertEqual(json.loads(b)['counter'], 1)
                finally:
                    srv2.stop()
        # 全部场景结束后: 不存在已提交 nonce 但业务未做的状态
        orphan = db_rows(self.db,
                         'SELECT COUNT(*) FROM nonces n WHERE NOT EXISTS '
                         "(SELECT 1 FROM audit a WHERE a.identity_id=n.identity_id "
                         "AND a.nonce=n.nonce AND a.result='success')")[0][0]
        self.assertEqual(orphan, 0)


if __name__ == '__main__':
    unittest.main()
