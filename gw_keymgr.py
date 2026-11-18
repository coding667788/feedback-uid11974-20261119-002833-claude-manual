#!/usr/bin/env python3
"""密钥 / 服务身份管理命令行。

安全约定: 密钥明文仅在创建时通过 --out 文件(或 stdout)交付一次,
不写入任何日志; list 等命令绝不输出密钥。
"""
from __future__ import annotations

import argparse
import json
import secrets
import sys
import time

import gw_db


def _insert_key(conn, identity_id):
    key_id = 'key_' + secrets.token_hex(8)
    secret = secrets.token_bytes(32)
    conn.execute(
        'INSERT INTO keys(key_id, identity_id, secret, status, created_at) '
        'VALUES (?,?,?,?,?)', (key_id, identity_id, secret, 'active', time.time()))
    return {'key_id': key_id, 'secret_hex': secret.hex()}


def _emit(a, obj):
    text = json.dumps(obj, ensure_ascii=False, indent=2)
    if getattr(a, 'out', None):
        with open(a.out, 'w', encoding='utf-8') as f:
            f.write(text)
        print('written: %s' % a.out)
    else:
        print(text)
    print('WARNING: 输出含明文密钥, 仅此一次交付, 请妥善保管, 勿提交版本库',
          file=sys.stderr)


def _fail(msg):
    print('error: %s' % msg, file=sys.stderr)
    sys.exit(1)


def _find_identity(conn, spec):
    parts = spec.split(':', 1)
    if len(parts) != 2 or not all(parts):
        _fail('identity 格式应为 tenant:name, 得到 %r' % spec)
    row = conn.execute(
        'SELECT id, status FROM identities WHERE tenant = ? AND name = ?',
        (parts[0], parts[1])).fetchone()
    if row is None:
        _fail('identity 不存在: %s' % spec)
    return row


def cmd_init(a):
    gw_db.init_db(a.db)
    print('ok: initialized %s' % a.db)


def cmd_seed(a):
    """预置演示租户 / 服务身份 / 初始密钥(跨租户同名身份)。"""
    gw_db.init_db(a.db)
    conn = gw_db.connect(a.db)
    out = {}
    try:
        conn.execute('BEGIN IMMEDIATE')
        for tenant, name in (('t_alpha', 'svc'), ('t_beta', 'svc')):
            row = conn.execute(
                'SELECT id FROM identities WHERE tenant = ? AND name = ?',
                (tenant, name)).fetchone()
            if row is not None:
                _fail('已存在 %s:%s, seed 需要全新数据库' % (tenant, name))
            cur = conn.execute(
                'INSERT INTO identities(tenant, name, status) VALUES (?,?,?)',
                (tenant, name, 'active'))
            out['%s:%s' % (tenant, name)] = _insert_key(conn, cur.lastrowid)
        conn.commit()
    finally:
        conn.close()
    _emit(a, out)


def cmd_identity_add(a):
    conn = gw_db.connect(a.db)
    try:
        conn.execute('BEGIN IMMEDIATE')
        row = conn.execute(
            'SELECT id FROM identities WHERE tenant = ? AND name = ?',
            (a.tenant, a.name)).fetchone()
        if row is not None:
            _fail('identity 已存在: %s:%s' % (a.tenant, a.name))
        cur = conn.execute(
            'INSERT INTO identities(tenant, name, status) VALUES (?,?,?)',
            (a.tenant, a.name, 'active'))
        k = _insert_key(conn, cur.lastrowid)
        conn.commit()
    finally:
        conn.close()
    _emit(a, {'tenant': a.tenant, 'name': a.name, **k})


def cmd_key_new(a):
    """为身份启用一把新密钥; 同一身份最多同时持有新旧两把有效密钥。"""
    conn = gw_db.connect(a.db)
    try:
        conn.execute('BEGIN IMMEDIATE')
        iid, istatus = _find_identity(conn, a.identity)
        if istatus != 'active':
            _fail('identity 已禁用, 请先启用: %s' % a.identity)
        n = conn.execute(
            "SELECT COUNT(*) FROM keys WHERE identity_id = ? AND status = 'active'",
            (iid,)).fetchone()[0]
        if n >= 2:
            _fail('该身份已有新旧两把有效密钥, 请先 key-revoke 撤销一把')
        k = _insert_key(conn, iid)
        conn.commit()
    finally:
        conn.close()
    _emit(a, {'identity': a.identity, **k})


def cmd_key_revoke(a):
    conn = gw_db.connect(a.db)
    try:
        conn.execute('BEGIN IMMEDIATE')
        cur = conn.execute(
            "UPDATE keys SET status = 'revoked' WHERE key_id = ? AND status = 'active'",
            (a.key_id,))
        if cur.rowcount == 0:
            conn.rollback()
            _fail('key 不存在或已撤销: %s' % a.key_id)
        conn.commit()
    finally:
        conn.close()
    print('ok: revoked %s' % a.key_id)


def _set_identity_status(a, status):
    conn = gw_db.connect(a.db)
    try:
        conn.execute('BEGIN IMMEDIATE')
        iid, _ = _find_identity(conn, a.identity)
        conn.execute('UPDATE identities SET status = ? WHERE id = ?', (status, iid))
        conn.commit()
    finally:
        conn.close()
    print('ok: %s -> %s' % (a.identity, status))


def cmd_identity_disable(a):
    _set_identity_status(a, 'disabled')


def cmd_identity_enable(a):
    _set_identity_status(a, 'active')


def cmd_list(a):
    conn = gw_db.connect(a.db)
    try:
        rows = conn.execute(
            'SELECT id, tenant, name, status FROM identities ORDER BY id').fetchall()
        for iid, tenant, name, st in rows:
            c = conn.execute('SELECT value FROM counters WHERE identity_id = ?',
                             (iid,)).fetchone()
            print('identity %s:%s [%s] counter=%d'
                  % (tenant, name, st, c[0] if c else 0))
            for key_id, kst, created in conn.execute(
                    'SELECT key_id, status, created_at FROM keys '
                    'WHERE identity_id = ? ORDER BY created_at', (iid,)):
                print('  key %s [%s] created=%.0f' % (key_id, kst, created))
    finally:
        conn.close()


def main():
    ap = argparse.ArgumentParser(description='网关密钥/身份管理')
    ap.add_argument('--db', required=True)
    sub = ap.add_subparsers(dest='cmd', required=True)

    sub.add_parser('init').set_defaults(fn=cmd_init)

    p = sub.add_parser('seed', help='预置演示租户/身份/密钥')
    p.add_argument('--out')
    p.set_defaults(fn=cmd_seed)

    p = sub.add_parser('identity-add')
    p.add_argument('--tenant', required=True)
    p.add_argument('--name', required=True)
    p.add_argument('--out')
    p.set_defaults(fn=cmd_identity_add)

    p = sub.add_parser('key-new')
    p.add_argument('--identity', required=True, help='tenant:name')
    p.add_argument('--out')
    p.set_defaults(fn=cmd_key_new)

    p = sub.add_parser('key-revoke')
    p.add_argument('--key-id', required=True)
    p.set_defaults(fn=cmd_key_revoke)

    p = sub.add_parser('identity-disable')
    p.add_argument('--identity', required=True)
    p.set_defaults(fn=cmd_identity_disable)

    p = sub.add_parser('identity-enable')
    p.add_argument('--identity', required=True)
    p.set_defaults(fn=cmd_identity_enable)

    sub.add_parser('list').set_defaults(fn=cmd_list)

    a = ap.parse_args()
    a.fn(a)


if __name__ == '__main__':
    main()
