"""Standalone signing HTTP client.

It builds the canonical signing input itself (no gateway code imported other
than the public signing helpers, which the tests re-implement independently
too), sends a real HTTP request over a socket and returns the response.

Library use::

    c = SigningClient("http://127.0.0.1:8080", key_id, secret)
    c.request("POST", "/v1/accounts/a1/increment", body=b"")

CLI::

    python -m gateway.client --base-url http://127.0.0.1:8080 \
        --key-id ak_... --secret ... POST /v1/accounts/a1/increment
"""

from __future__ import annotations

import argparse
import hashlib
import hmac
import http.client
import json
import os
import sys
import time
from dataclasses import dataclass, field
from typing import Iterable, Mapping
from urllib.parse import urlsplit


def make_nonce() -> str:
    """32 random bytes -> 43 base64url chars (256 bits of entropy)."""
    import base64
    return base64.urlsafe_b64encode(os.urandom(32)).rstrip(b"=").decode("ascii")


def canonical_input(method: str, target: str, timestamp: str, nonce: str,
                    body_sha256: str) -> bytes:
    return b"\n".join((
        method.encode("ascii"),
        target.encode("ascii"),
        timestamp.encode("ascii"),
        nonce.encode("ascii"),
        body_sha256.encode("ascii"),
    ))


@dataclass
class Response:
    status: int
    headers: dict[str, str]
    body: bytes
    json: dict | None = None
    error: str | None = None

    def __post_init__(self) -> None:
        if self.body:
            try:
                self.json = json.loads(self.body.decode("utf-8"))
            except Exception:
                self.json = None

    def code(self) -> str | None:
        return (self.json or {}).get("error")


@dataclass
class SigningClient:
    base_url: str
    key_id: str
    secret: str
    timeout: float = 30.0
    clock: callable = time.time
    _base: tuple = field(init=False)

    def __post_init__(self) -> None:
        u = urlsplit(self.base_url)
        if u.scheme != "http" or not u.hostname:
            raise ValueError("base_url must be http://host[:port]")
        self._base = (u.hostname, u.port or 80)

    def build_headers(self, method: str, target: str, body: bytes, *,
                      timestamp: int | None = None, nonce: str | None = None,
                      body_sha256: str | None = None,
                      signature: str | None = None,
                      extra: Mapping[str, str] | None = None) -> dict[str, str]:
        ts = str(int(timestamp if timestamp is not None else self.clock()))
        n = nonce if nonce is not None else make_nonce()
        bsha = body_sha256 if body_sha256 is not None else hashlib.sha256(body).hexdigest()
        sig = signature
        if sig is None:
            msg = canonical_input(method, target, ts, n, bsha)
            sig = hmac.new(self.secret.encode(), msg, hashlib.sha256).hexdigest()
        h = {
            "key_id": self.key_id,
            "timestamp": ts,
            "nonce": n,
            "body_sha256": bsha,
            "signature": sig,
        }
        if extra:
            h.update(extra)
        return h

    def request(self, method: str, target: str, body: bytes = b"", *,
                headers: Mapping[str, str] | None = None,
                extra_pairs: Iterable[tuple[str, str]] | None = None,
                omit: Iterable[str] = (),
                timestamp: int | None = None, nonce: str | None = None,
                timeout: float | None = None) -> Response:
        h = self.build_headers(method, target, body, timestamp=timestamp,
                               nonce=nonce)
        if headers:
            h.update(headers)
        for name in omit:
            h.pop(name, None)
        pairs = list(h.items())
        if extra_pairs:
            pairs.extend(extra_pairs)
        return self.send(method, target, body, pairs, timeout=timeout)

    def send(self, method: str, target: str, body: bytes,
             headers: Mapping[str, str] | Iterable[tuple[str, str]],
             timeout: float | None = None) -> Response:
        """``headers`` may be a list of pairs, so duplicates can be sent."""
        pairs = list(headers.items()) if isinstance(headers, Mapping) else list(headers)
        names = {k.lower() for k, _ in pairs}
        if "content-length" not in names:
            pairs.append(("Content-Length", str(len(body))))
        if "connection" not in names:
            pairs.append(("Connection", "close"))
        conn = http.client.HTTPConnection(*self._base,
                                          timeout=timeout or self.timeout)
        try:
            conn.putrequest(method, target, skip_accept_encoding=True)
            for k, v in pairs:
                conn.putheader(k, v)
            conn.endheaders()
            if body:
                conn.send(body)
            r = conn.getresponse()
            data = r.read()
            return Response(status=r.status,
                            headers={k.lower(): v for k, v in r.getheaders()},
                            body=data)
        except (ConnectionError, OSError, http.client.HTTPException) as exc:
            return Response(status=0, headers={}, body=b"",
                            error=f"{type(exc).__name__}: {exc}")
        finally:
            try:
                conn.close()
            except Exception:
                pass


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description="Signed HTTP client for the gateway")
    p.add_argument("--base-url", default="http://127.0.0.1:8080")
    p.add_argument("--key-id", required=True)
    p.add_argument("--secret", required=True)
    p.add_argument("--body", default="")
    p.add_argument("--timestamp", type=int)
    p.add_argument("--nonce")
    p.add_argument("method")
    p.add_argument("target")
    args = p.parse_args(argv)
    body = args.body.encode("utf-8")
    c = SigningClient(args.base_url, args.key_id, args.secret)
    r = c.request(args.method, args.target, body,
                  timestamp=args.timestamp, nonce=args.nonce)
    print(f"status={r.status}")
    if r.body:
        print(r.body.decode("utf-8", "replace"))
    return 0 if r.status == 200 else 1


if __name__ == "__main__":
    raise SystemExit(main())
