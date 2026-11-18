"""Signature protocol: parsing, canonical input construction, verification.

Canonical signing input (ASCII bytes)::

    METHOD + b"\\n" + request_target + b"\\n" + timestamp + b"\\n"
           + nonce + b"\\n" + body_sha256

* METHOD is the request method upper-cased.  Anything that is not an ASCII
  token is rejected before canonicalisation.
* request_target is the *raw* request target exactly as it appeared on the
  request line: path and query string are not decoded, sorted or re-encoded.
* timestamp is the decimal ASCII representation of a Unix time in seconds,
  canonical form only: ``0`` or a non-zero digit followed by digits, no sign,
  no leading zero, no whitespace, bounded length.
* nonce is an ASCII string of 22..128 characters from a conservative symbol
  set; 22 base64url characters carry 132 bits, so 128 bits of entropy is the
  minimum we accept (clients use 32 random bytes -> 43 chars).
* body_sha256 is the lowercase hex SHA-256 of the exact bytes received.

The signature header value is ``hex( HMAC-SHA256(secret, signing_input) )``,
64 lowercase hex characters.
"""

from __future__ import annotations

import hashlib
import hmac
import re
from dataclasses import dataclass
from typing import Mapping

AUTH_HEADERS = ("key_id", "timestamp", "nonce", "body_sha256", "signature")

KEY_ID_RE = re.compile(r"^[A-Za-z0-9._:-]{1,128}$")
NONCE_RE = re.compile(r"^[A-Za-z0-9._~-]{22,128}$")
HEX64_RE = re.compile(r"^[0-9a-f]{64}$")
TS_RE = re.compile(r"^(?:0|[1-9][0-9]{0,15})$")
SIGNATURE_RE = re.compile(r"^[0-9a-f]{64}$")
METHOD_RE = re.compile(r"^[A-Z][A-Z0-9_-]{0,31}$")

MAX_TIMESTAMP = 10**12            # year ~33658; keeps int() and the window small
CLOCK_SKEW_SECONDS = 60
MAX_BODY_BYTES = 1024 * 1024


class SignatureError(Exception):
    def __init__(self, code: str, message: str = "") -> None:
        super().__init__(message or code)
        self.code = code
        self.message = message or code


@dataclass(frozen=True)
class AuthHeaders:
    key_id: str
    timestamp: int
    timestamp_text: str
    nonce: str
    body_sha256: str
    signature: str

    def signing_input(self, method: str, request_target: str) -> bytes:
        left = b"\n".join((
            method.encode("ascii"),
            request_target.encode("ascii"),
            self.timestamp_text.encode("ascii"),
            self.nonce.encode("ascii"),
            self.body_sha256.encode("ascii"),
        ))
        return left


def normalized_method(method: str) -> str:
    upper = method.upper()
    if not upper.isascii() or not METHOD_RE.match(upper):
        raise SignatureError("method_invalid", "method is not an ASCII token")
    return upper


def validate_request_target(target: str) -> str:
    """Reject anything that is not a whitespace-free ASCII request target."""
    if not target:
        raise SignatureError("target_invalid", "empty request target")
    try:
        raw = target.encode("ascii")
    except UnicodeEncodeError:
        raise SignatureError("target_invalid", "request target must be ASCII") from None
    if len(raw) > 8192:
        raise SignatureError("target_invalid", "request target too long")
    if any(b <= 0x20 or b == 0x7F for b in raw):
        raise SignatureError("target_invalid", "request target must not contain whitespace or controls")
    # No scheme/host form: origin-form only, but '/' is not mandated because a
    # gateway may also front OPTIONS *; anything absolute is refused outright.
    if not (target.startswith("/") or target == "*"):
        raise SignatureError("target_invalid", "request target must be origin-form")
    return target


def parse_auth_headers(headers: Mapping[str, list[str] | str], *,
                       require: bool = True) -> AuthHeaders | None:
    """Parse the five required auth headers.

    ``headers`` must be a multi-value mapping (name -> list of values), so
    duplicated headers are detectable.  Header names are matched
    case-insensitively by the caller-provided mapping; the gateway lowercases
    them.
    """
    values: dict[str, str] = {}
    for name in AUTH_HEADERS:
        raw = headers.get(name)
        if raw is None:
            if require:
                raise SignatureError("missing_header", f"missing header {name}")
            continue
        if isinstance(raw, str):
            raise SignatureError("duplicate_header", f"duplicate header {name}")
        if len(raw) > 1:
            raise SignatureError("duplicate_header", f"duplicate header {name}")
        if len(raw) == 0:
            raise SignatureError("invalid_header", f"empty header {name}")
        v = raw[0]
        # Header values are stripped of surrounding OWS by the HTTP parser
        # already; any embedded control character is malformed.
        if any(ord(ch) < 0x20 and ch != "\t" for ch in v) or any(ord(ch) == 0x7F for ch in v):
            raise SignatureError("invalid_header", f"control character in {name}")
        values[name] = v

    key_id = values["key_id"]
    if not KEY_ID_RE.match(key_id):
        raise SignatureError("invalid_key_id", "key_id is not canonical")

    ts_text = values["timestamp"]
    if not TS_RE.match(ts_text) or int(ts_text) > MAX_TIMESTAMP:
        raise SignatureError("invalid_timestamp", "timestamp must be canonical decimal seconds")

    nonce = values["nonce"]
    if not NONCE_RE.match(nonce):
        raise SignatureError("invalid_nonce",
                             "nonce must be 22..128 URL-safe ASCII characters (>=128 bits)")

    body_sha = values["body_sha256"]
    if not HEX64_RE.match(body_sha):
        raise SignatureError("invalid_body_sha256", "body_sha256 must be 64 lowercase hex characters")

    signature = values["signature"]
    if not SIGNATURE_RE.match(signature):
        raise SignatureError("invalid_signature", "signature must be 64 lowercase hex characters")

    return AuthHeaders(key_id=key_id, timestamp=int(ts_text), timestamp_text=ts_text,
                       nonce=nonce, body_sha256=body_sha, signature=signature)


def compute_body_sha256(body: bytes) -> str:
    return hashlib.sha256(body).hexdigest()


def sign(secret: str, method: str, request_target: str, timestamp: int,
         nonce: str, body: bytes) -> tuple[str, str]:
    """Return (body_sha256_hex, signature_hex) for a request."""
    method = normalized_method(method)
    validate_request_target(request_target)
    ts_text = str(int(timestamp))
    body_sha = compute_body_sha256(body)
    msg = b"\n".join((method.encode("ascii"), request_target.encode("ascii"),
                      ts_text.encode("ascii"), nonce.encode("ascii"),
                      body_sha.encode("ascii")))
    sig = hmac.new(secret.encode("utf-8"), msg, hashlib.sha256).hexdigest()
    return body_sha, sig


def verify_signature(secret: str, method: str, request_target: str,
                     auth: AuthHeaders, body_sha256: str) -> bool:
    """Constant-time HMAC verification against the *actual* received body hash."""
    if not hmac.compare_digest(auth.body_sha256, body_sha256):
        # The header hash must equal the body hash; otherwise the signed input
        # would not describe the bytes we are about to process.
        return False
    expected = hmac.new(
        secret.encode("utf-8"),
        auth.signing_input(normalized_method(method), validate_request_target(request_target)),
        hashlib.sha256,
    ).hexdigest()
    return hmac.compare_digest(expected, auth.signature)
