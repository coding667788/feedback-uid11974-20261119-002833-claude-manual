#!/usr/bin/env python3
"""独立签名客户端: 对请求做 HMAC-SHA256 签名并发送。

示例:
  python gw_client.py --url http://127.0.0.1:8001/v1/counter/increment \
      --method POST --key-id key_xxx --secret-hex <64hex>
  python gw_client.py --url "http://127.0.0.1:8001/v1/counter?from=cli" --method GET ...
 ...
"""
from __future__ import annotations

import argparse
import hashlib
import http.client
import os
import secrets
import sys
import time
from urllib.parse import urlsplit

import gw_protocol as P


def build_headers(key_id, secret_hex, method, target, body=b'',
                  timestamp=None, nonce=None):
    """构造 5 个认证头; target 必须是要原样发送的 request-target。"""
    ts = int(time.time()) if timestamp is None else int(timestamp)
    nonce = nonce or secrets.token_hex(16)   # 128 比特随机
    body_sha = hashlib.sha256(body).hexdigest()
    sig = P.sign_hex(bytes.fromhex(secret_hex), method.upper(), target,
                     ts, nonce, body_sha)
    return [
        (P.H_KEY_ID, key_id),
        (P.H_TIMESTAMP, str(ts)),
        (P.H_NONCE, nonce),
        (P.H_BODY_SHA256, body_sha),
        (P.H_SIGNATURE, sig),
    ]


def main():
    ap = argparse.ArgumentParser(description='网关签名客户端')
    ap.add_argument('--url', required=True)
    ap.add_argument('--method', default='POST')
    ap.add_argument('--key-id', required=True)
    ap.add_argument('--secret-hex', default=os.environ.get('GW_SECRET_HEX'),
                    help='也可通过环境变量 GW_SECRET_HEX 提供')
    ap.add_argument('--secret-file', help='内含 secret hex 的文件')
    ap.add_argument('--body', default='')
    ap.add_argument('--body-file')
    ap.add_argument('--timestamp', type=int, default=None)
    ap.add_argument('--nonce', default=None)
    a = ap.parse_args()

    secret = a.secret_hex
    if a.secret_file:
        with open(a.secret_file, 'r', encoding='ascii') as f:
            secret = f.read().strip()
    if not secret:
        ap.error('需要 --secret-hex / --secret-file / 环境变量 GW_SECRET_HEX')

    if a.body_file:
        with open(a.body_file, 'rb') as f:
            body = f.read()
    else:
        body = a.body.encode('utf-8')

    u = urlsplit(a.url)   # urlsplit 不解码查询串, target 保持原始形式
    target = u.path or '/'
    if u.query:
        target += '?' + u.query
    method = a.method.upper()

    headers = build_headers(a.key_id, secret, method, target, body,
                            a.timestamp, a.nonce)
    conn = http.client.HTTPConnection(u.hostname, u.port or 80, timeout=15)
    conn.putrequest(method, target, skip_accept_encoding=True)
    for k, v in headers:
        conn.putheader(k, v)
    conn.putheader('Content-Length', str(len(body)))
    conn.endheaders(body)
    resp = conn.getresponse()
    data = resp.read()
    conn.close()
    print('HTTP %d' % resp.status)
    sys.stdout.write(data.decode('utf-8', 'replace') + '\n')
    return 0 if resp.status < 400 else 1


if __name__ == '__main__':
    sys.exit(main())
