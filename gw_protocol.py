"""签名协议:HMAC-SHA256 规范串与字段校验(网关 / 客户端 / 测试共用)。

规范串(ASCII 字节):
    method "\n" request-target "\n" timestamp "\n" nonce "\n" body_sha256

- method: 大写 HTTP 方法
- request-target: 原始路径+查询串, 不解码 / 不排序 / 不重新编码
- timestamp: 十进制整数秒, 规范形式(无前导零 / 符号 / 空白)
- nonce: 32 位小写十六进制(128 比特随机)
- body_sha256: 实际收到请求体的 SHA256 小写十六进制(64 字符)
- signature: HMAC-SHA256(secret, 规范串) 小写十六进制(64 字符)
"""
from __future__ import annotations

import hashlib
import hmac
import re

MAX_BODY_BYTES = 1 << 20          # 请求体上限 1 MiB
SKEW_SECONDS = 60                 # timestamp 允许的前后偏移(秒)
MAX_TARGET_LEN = 2048             # request-target 长度上限

H_KEY_ID = 'X-Key-Id'
H_TIMESTAMP = 'X-Timestamp'
H_NONCE = 'X-Nonce'
H_BODY_SHA256 = 'X-Body-Sha256'
H_SIGNATURE = 'X-Signature'
AUTH_HEADERS = (H_KEY_ID, H_TIMESTAMP, H_NONCE, H_BODY_SHA256, H_SIGNATURE)

_KEY_ID_RE = re.compile(r'^[A-Za-z0-9_-]{1,64}$')
_TS_RE = re.compile(r'^(0|[1-9][0-9]{0,14})$')   # 规范十进制: 无前导零/符号, 限长
_NONCE_RE = re.compile(r'^[0-9a-f]{32}$')        # 128 比特, 小写十六进制
_HEX64_RE = re.compile(r'^[0-9a-f]{64}$')


class ProtocolError(Exception):
    """字段非法(对应 HTTP 400)。"""

    def __init__(self, reason):
        super().__init__(reason)
        self.reason = reason


def _check_ascii(s, what):
    if not isinstance(s, str) or not s.isascii():
        raise ProtocolError('%s: 必须是 ASCII' % what)


def validate_key_id(v):
    _check_ascii(v, 'key_id')
    if not _KEY_ID_RE.match(v):
        raise ProtocolError('key_id: 非法(仅允许 1-64 位 [A-Za-z0-9_-])')
    return v


def validate_timestamp(v):
    _check_ascii(v, 'timestamp')
    if not _TS_RE.match(v):
        raise ProtocolError('timestamp: 非规范十进制(前导零/符号/空白/超长均拒绝)')
    return int(v)


def validate_nonce(v):
    _check_ascii(v, 'nonce')
    if not _NONCE_RE.match(v):
        raise ProtocolError('nonce: 必须是 32 位小写十六进制(128 比特随机数)')
    return v


def validate_body_sha256(v):
    _check_ascii(v, 'body_sha256')
    if not _HEX64_RE.match(v):
        raise ProtocolError('body_sha256: 必须是 64 位小写十六进制')
    return v


def validate_signature(v):
    _check_ascii(v, 'signature')
    if not _HEX64_RE.match(v):
        raise ProtocolError('signature: 必须是 64 位小写十六进制')
    return v


def validate_target(t):
    """request-target: 无空白 ASCII, origin-form, 原样参与签名。"""
    _check_ascii(t, 'request-target')
    if not t or len(t) > MAX_TARGET_LEN:
        raise ProtocolError('request-target: 为空或超长(>%d)' % MAX_TARGET_LEN)
    if not t.startswith('/'):
        raise ProtocolError('request-target: 仅支持 origin-form(以 / 开头)')
    for ch in t:
        o = ord(ch)
        if o < 0x21 or o > 0x7E:
            raise ProtocolError('request-target: 含空白或控制字符')
    return t


def body_sha256_hex(body: bytes) -> str:
    return hashlib.sha256(body).hexdigest()


def canonical_string(method, target, timestamp, nonce, body_sha) -> bytes:
    return ('%s\n%s\n%d\n%s\n%s' % (method, target, timestamp, nonce, body_sha)).encode('ascii')


def sign_hex(secret: bytes, method, target, timestamp, nonce, body_sha) -> str:
    msg = canonical_string(method, target, timestamp, nonce, body_sha)
    return hmac.new(secret, msg, hashlib.sha256).hexdigest()


def verify_hex(secret: bytes, provided, method, target, timestamp, nonce, body_sha) -> bool:
    expected = sign_hex(secret, method, target, timestamp, nonce, body_sha)
    return hmac.compare_digest(expected, provided)
