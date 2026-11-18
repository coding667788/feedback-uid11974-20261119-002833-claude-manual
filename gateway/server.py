"""HTTP gateway: authentication, replay protection and the protected write.

Atomicity model
---------------
A request is handled in two phases.

**Phase A -- authentication** (read-only).  Header validation, body hash,
timestamp window, routing, then a read of the key and identity rows followed
by HMAC verification.  Nothing is written, so a failed signature or an
unauthorised target never occupies a nonce.

**Phase B -- protected write** (one ``BEGIN IMMEDIATE`` transaction).  The
key and identity state are *re-read* (the request may have been authenticated
before an operator revoked the key or disabled the identity), then, in order:

1. state re-check (``enabled`` / ``active``), fail if changed,
2. HMAC re-verification against the re-read key record,
3. the nonce INSERT (replay is a PRIMARY KEY constraint, not check-then-act),
4. the business write (account counter increment),
5. one audit row,
6. COMMIT.

SQLite has a single writer, so a revoke that committed before Phase B is
seen by the re-read; one that tries to commit during Phase B waits until after
this commit and therefore cannot slip between the check and the write.  HTTP
responses are written only after COMMIT, so a client never sees ``ok`` for a
rolled-back transaction.

Failure injection (used by the real-process tests)
--------------------------------------------------
Environment variables read at startup:

* ``GW_CRASH_POINT`` = ``after_nonce`` | ``before_commit`` | ``after_commit``
* ``GW_CRASH_ACCOUNT`` restricts the crash to requests for one account
* ``GW_HOLD_BEFORE_WRITE_MS`` sleeps between Phase A and Phase B (the window
  in which an operator revoke can commit)
* ``GW_HOLD_BEFORE_COMMIT_MS`` sleeps inside the transaction before COMMIT

The crash uses ``os._exit`` on the real child process, so SQLite sees exactly
what a power loss sees.  The HTTP client gets a closed connection.
"""

from __future__ import annotations

import json
import os
import sqlite3
import sys
import threading
import time
import traceback
from dataclasses import dataclass
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any, Callable

from .signing import (
    CLOCK_SKEW_SECONDS, MAX_BODY_BYTES, AuthHeaders, SignatureError,
    compute_body_sha256, normalized_method, parse_auth_headers,
    validate_request_target, verify_signature,
)
from .store import DB, GatewayError, audit, unseal_secret

ACCEPT_EVENT = "request_accepted"
REJECT_EVENT = "request_rejected"

# A row is only purgeable once every request that could still carry its
# timestamp is outside the window: request_ts <= accepted_at + 60, and such a
# request is acceptable while now <= request_ts + 60, so accepted_at + 120 is
# the last moment it could matter.  Keep a margin on top.
NONCE_RETENTION_SECONDS = 2 * CLOCK_SKEW_SECONDS + 10


@dataclass
class GatewayConfig:
    db_path: str
    pepper: bytes
    host: str = "127.0.0.1"
    port: int = 0
    clock: Callable[[], float] | None = None
    crash_point: str | None = None
    crash_account: str | None = None
    hold_before_write_ms: int = 0
    hold_before_commit_ms: int = 0


class MonotonicClock:
    """Non-decreasing view of a (possibly injected) wall clock."""

    def __init__(self, source: Callable[[], float] = time.time) -> None:
        self._source = source
        self._last: float | None = None
        self._lock = threading.Lock()

    def now(self) -> float:
        with self._lock:
            raw = float(self._source())
            if self._last is not None and raw < self._last:
                return self._last
            self._last = raw
            return raw


class CrashInjector:
    def __init__(self, point: str | None, account: str | None,
                 hold_before_write_ms: int, hold_before_commit_ms: int) -> None:
        self.point = point or None
        self.account = account
        self.hold_before_write_ms = max(0, int(hold_before_write_ms or 0))
        self.hold_before_commit_ms = max(0, int(hold_before_commit_ms or 0))
        self._fired = False
        self._lock = threading.Lock()

    def hold_between_phases(self) -> None:
        if self.hold_before_write_ms:
            time.sleep(self.hold_before_write_ms / 1000.0)

    def hold_before_commit(self) -> None:
        if self.hold_before_commit_ms:
            time.sleep(self.hold_before_commit_ms / 1000.0)

    def maybe_crash(self, point: str, account: str | None = None) -> None:
        if self.point != point:
            return
        if self.account is not None and account != self.account:
            return
        with self._lock:
            if self._fired:
                return
            self._fired = True
        try:
            sys.stderr.write(f"CRASH_POINT_HIT {point} account={account}\n")
            sys.stderr.flush()
        except Exception:
            pass
        os._exit(97)


# ---------------------------------------------------------------------------
# Business layer (runs only inside the caller's write transaction)
# ---------------------------------------------------------------------------

def increment_account(conn: sqlite3.Connection, tenant_id: str, account_id: str,
                      now_epoch: float) -> int:
    row = conn.execute(
        "SELECT counter FROM accounts WHERE tenant_id=? AND account_id=?",
        (tenant_id, account_id)).fetchone()
    if row is None:
        raise GatewayError(404, "account_not_found", "account does not exist")
    new = int(row["counter"]) + 1
    conn.execute("UPDATE accounts SET counter=?, updated_at=? "
                 "WHERE tenant_id=? AND account_id=?",
                 (new, time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(now_epoch)),
                  tenant_id, account_id))
    return new


def read_account(conn: sqlite3.Connection, tenant_id: str, account_id: str) -> int:
    row = conn.execute(
        "SELECT counter FROM accounts WHERE tenant_id=? AND account_id=?",
        (tenant_id, account_id)).fetchone()
    if row is None:
        raise GatewayError(404, "account_not_found", "account does not exist")
    return int(row["counter"])


def purge_nonces(conn: sqlite3.Connection, now: float) -> int:
    cur = conn.execute(
        "DELETE FROM nonces WHERE accepted_at < ?",
        (now - NONCE_RETENTION_SECONDS,))
    return cur.rowcount or 0


# ---------------------------------------------------------------------------
# Routing
# ---------------------------------------------------------------------------

_SAFE_ACCOUNT = set("._-")


def parse_business_path(target: str) -> tuple[str, str]:
    """Return (route, account_id) for the raw origin-form target.

    Only ``/v1/accounts/{id}/increment`` (POST) and ``/v1/accounts/{id}``
    (GET) exist.  The account id is percent-decoded only after the signature
    has been checked over the raw target, then constrained to a plain token,
    so encoded slashes or ``..`` cannot escape the route.
    """
    from urllib.parse import unquote

    if not target.startswith("/"):
        raise GatewayError(404, "not_found", "route not found")
    raw_path = target.split("?", 1)[0]
    parts = raw_path.split("/")
    if len(parts) == 5 and parts[1] == "v1" and parts[2] == "accounts" and parts[4] == "increment":
        route, raw_account = "increment", parts[3]
    elif len(parts) == 4 and parts[1] == "v1" and parts[2] == "accounts":
        route, raw_account = "get", parts[3]
    else:
        raise GatewayError(404, "not_found", "route not found")
    account = unquote(raw_account)
    if (not account or account in (".", "..")
            or any(not (c.isascii() and (c.isalnum() or c in _SAFE_ACCOUNT))
                   for c in account)):
        raise GatewayError(404, "bad_account", "account id is not a plain token")
    return route, account


# ---------------------------------------------------------------------------
# Server
# ---------------------------------------------------------------------------

class GatewayServer(ThreadingHTTPServer):
    daemon_threads = True
    allow_reuse_address = True

    def __init__(self, cfg: GatewayConfig) -> None:
        self.cfg = cfg
        self.db = DB(cfg.db_path)
        self.db.init_schema()
        self.clock = MonotonicClock(cfg.clock or time.time)
        self.crash = CrashInjector(cfg.crash_point, cfg.crash_account,
                                   cfg.hold_before_write_ms,
                                   cfg.hold_before_commit_ms)
        self._purge_stop = threading.Event()
        with self.db.immediate() as conn:
            purge_nonces(conn, self.clock.now())
        super().__init__((cfg.host, cfg.port), GatewayHandler)
        self._purge_thread = threading.Thread(target=self._purge_loop, daemon=True,
                                              name="nonce-purge")
        self._purge_thread.start()

    def _purge_loop(self) -> None:
        while not self._purge_stop.wait(30.0):
            try:
                with self.db.immediate() as conn:
                    purge_nonces(conn, self.clock.now())
            except Exception:
                pass

    def server_close(self) -> None:
        self._purge_stop.set()
        try:
            self.db.close()
        finally:
            super().server_close()


class GatewayHandler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    server_version = "localauthgw/1.0"
    sys_version = ""

    def log_message(self, fmt: str, *args: Any) -> None:
        # Only the request line is logged; header values (signatures, key ids,
        # nonces) and bodies are never logged.
        sys.stderr.write("%s - %s\n" % (self.address_string(), fmt % args))

    # -- helpers ----------------------------------------------------------
    @property
    def srv(self) -> GatewayServer:
        return self.server  # type: ignore[return-value]

    def _read_body(self) -> bytes:
        cl = self.headers.get("Content-Length")
        if cl is None:
            raise SignatureError("body_length_required", "Content-Length is required")
        if not cl.isascii() or not cl.isdigit() or (len(cl) > 1 and cl[0] == "0"):
            raise SignatureError("body_length_invalid", "Content-Length must be canonical decimal")
        n = int(cl)
        if n > MAX_BODY_BYTES:
            raise SignatureError("body_too_large", "request body exceeds 1 MiB")
        body = self.rfile.read(n) if n else b""
        if len(body) != n:
            raise SignatureError("body_truncated", "request body shorter than Content-Length")
        return body

    def _send_json(self, status: int, payload: dict[str, Any]) -> None:
        data = json.dumps(payload, ensure_ascii=True, separators=(",", ":")).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        self.send_header("Connection", "close")
        self.end_headers()
        self.wfile.write(data)
        self.wfile.flush()
        self.close_connection = True

    def _reject(self, status: int, code: str, message: str = "", *,
                stage: str = "handler", auth: AuthHeaders | None = None,
                target: str | None = None) -> None:
        now = self.srv.clock.now()
        try:
            with self.srv.db.immediate() as conn:
                audit(conn, REJECT_EVENT, at_epoch=now,
                      key_id=auth.key_id if auth else None,
                      nonce=auth.nonce if auth else None,
                      request_ts=auth.timestamp if auth else None,
                      rc=code,
                      detail=f"stage={stage} status={status} target={(target or '')[:512]}")
        except Exception:
            pass
        body: dict[str, Any] = {"error": code}
        if message:
            body["message"] = message
        self._send_json(status, body)

    # -- entry points -----------------------------------------------------
    def _handle(self, method: str) -> None:
        try:
            self._handle_inner(method)
        except (BrokenPipeError, ConnectionResetError):
            pass
        except Exception:
            traceback.print_exc(file=sys.stderr)
            try:
                self._send_json(500, {"error": "internal_error"})
            except Exception:
                pass

    def _handle_inner(self, method: str) -> None:
        raw_target = self.path  # exact request target, unmodified
        try:
            body = self._read_body()
        except SignatureError as exc:
            status = 413 if exc.code == "body_too_large" else 400
            self._reject(status, exc.code, exc.message, stage="body", target=raw_target)
            return

        try:
            target = validate_request_target(raw_target)
        except SignatureError as exc:
            self._reject(400, exc.code, exc.message, stage="target", target=raw_target)
            return
        try:
            norm_method = normalized_method(method)
        except SignatureError as exc:
            self._reject(405, exc.code, exc.message, stage="method", target=target)
            return

        hdrs = {name: (self.headers.get_all(name) or [])
                for name in ("key_id", "timestamp", "nonce", "body_sha256", "signature")}
        try:
            auth = parse_auth_headers(hdrs)
        except SignatureError as exc:
            self._reject(400, exc.code, exc.message, stage="headers", target=target)
            return
        assert auth is not None

        actual_body_sha = compute_body_sha256(body)
        if actual_body_sha != auth.body_sha256:
            self._reject(401, "body_mismatch",
                         "body_sha256 does not match the received body",
                         stage="body_hash", auth=auth, target=target)
            return

        received = self.srv.clock.now()
        if abs(received - auth.timestamp) > CLOCK_SKEW_SECONDS:
            self._reject(401, "timestamp_out_of_window",
                         "timestamp outside +/-60s of server receipt time",
                         stage="timestamp", auth=auth, target=target)
            return

        try:
            route, account_id = parse_business_path(target)
        except GatewayError as exc:
            self._reject(exc.status, exc.code, exc.message, stage="route",
                         auth=auth, target=target)
            return
        required_method = "POST" if route == "increment" else "GET"
        if norm_method != required_method:
            self._reject(405, "method_not_allowed",
                         f"{route} requires {required_method}", stage="route",
                         auth=auth, target=target)
            return

        # ---- Phase A: authenticate (read-only, nothing is written) -------
        try:
            row = _fetch_key(self.srv.db.conn(), auth.key_id)
        except sqlite3.OperationalError:
            self._reject(503, "db_busy", "could not read key state",
                         stage="auth_read", auth=auth, target=target)
            return
        err = _state_error(row)
        if err is not None:
            status, code, msg = err
            self._reject(status, code, msg, stage="auth", auth=auth, target=target)
            return
        assert row is not None
        if not _signature_ok(self.srv.cfg.pepper, row, auth, norm_method,
                             target, actual_body_sha):
            self._reject(401, "bad_signature", "signature did not verify",
                         stage="auth", auth=auth, target=target)
            return
        # Authenticated, but NOT admitted yet: this is the window in which a
        # revoke can commit and must still be honoured.
        self.srv.crash.hold_between_phases()

        # ---- Phase B: re-check and protect the write atomically ----------
        conn = self.srv.db.conn()
        try:
            conn.execute("BEGIN IMMEDIATE")
        except sqlite3.OperationalError:
            self._reject(503, "db_busy", "could not start transaction",
                         stage="begin", auth=auth, target=target)
            return
        try:
            # Re-read inside the write transaction: a revoke or disable that
            # committed after Phase A is visible here and the request fails.
            row2 = _fetch_key(conn, auth.key_id)
            err = _state_error(row2)
            if err is not None:
                conn.execute("ROLLBACK")
                status, code, msg = err
                self._reject(status, code, msg, stage="recheck", auth=auth,
                             target=target)
                return
            assert row2 is not None
            tenant_id = str(row2["tenant_id"])
            identity_uid = str(row2["identity_uid"])
            if not _signature_ok(self.srv.cfg.pepper, row2, auth, norm_method,
                                 target, actual_body_sha):
                conn.execute("ROLLBACK")
                self._reject(401, "bad_signature", "signature did not verify",
                             stage="recheck", auth=auth, target=target)
                return

            # Only now may the nonce be consumed.  The INSERT is the replay
            # check; a duplicate raises a PRIMARY KEY violation, so two
            # concurrent copies cannot both pass a read-then-insert race.
            try:
                conn.execute(
                    "INSERT INTO nonces(tenant_id,identity_uid,nonce,key_id,"
                    "request_ts,accepted_at,processed) VALUES(?,?,?,?,?,?,0)",
                    (tenant_id, identity_uid, auth.nonce, auth.key_id,
                     auth.timestamp, received))
            except sqlite3.IntegrityError as exc:
                conn.execute("ROLLBACK")
                msg = str(exc).upper()
                if "UNIQUE" in msg or "PRIMARY" in msg:
                    self._reject(409, "nonce_replayed",
                                 "nonce already used for this service identity",
                                 stage="nonce", auth=auth, target=target)
                else:
                    self._reject(400, "nonce_rejected", "nonce row rejected",
                                 stage="nonce", auth=auth, target=target)
                return

            self.srv.crash.maybe_crash("after_nonce", account_id)

            try:
                if route == "increment":
                    counter = increment_account(conn, tenant_id, account_id, received)
                else:
                    counter = read_account(conn, tenant_id, account_id)
            except GatewayError as exc:
                conn.execute("ROLLBACK")
                self._reject(exc.status, exc.code, exc.message, stage="business",
                             auth=auth, target=target)
                return

            self.srv.crash.hold_before_commit()
            self.srv.crash.maybe_crash("before_commit", account_id)

            conn.execute("UPDATE nonces SET processed=1 "
                         "WHERE tenant_id=? AND identity_uid=? AND nonce=?",
                         (tenant_id, identity_uid, auth.nonce))
            audit(conn, ACCEPT_EVENT, at_epoch=received, tenant_id=tenant_id,
                  identity_uid=identity_uid, key_id=auth.key_id,
                  account_id=account_id, nonce=auth.nonce,
                  request_ts=auth.timestamp, rc="ok",
                  detail=f"method={norm_method} route={route} counter={counter}")
            conn.execute("COMMIT")
        except BaseException:
            try:
                conn.execute("ROLLBACK")
            except Exception:
                pass
            raise

        # Commit succeeded.  Any response we send from here describes durable
        # state; a crash here means the client retries and gets 409 replay.
        self.srv.crash.maybe_crash("after_commit", account_id)
        self._send_json(200, {"status": "ok", "tenant": tenant_id,
                              "account": account_id, "counter": counter})

    def do_GET(self) -> None:
        self._handle("GET")

    def do_POST(self) -> None:
        self._handle("POST")

    def do_PUT(self) -> None:
        self._handle("PUT")

    def do_DELETE(self) -> None:
        self._handle("DELETE")

    def do_PATCH(self) -> None:
        self._handle("PATCH")


def _fetch_key(conn: sqlite3.Connection, key_id: str) -> sqlite3.Row | None:
    return conn.execute(
        "SELECT k.secret_sealed, k.state AS key_state,"
        "       i.identity_uid, i.tenant_id, i.enabled AS identity_enabled"
        "  FROM api_keys k JOIN service_identities i"
        "       ON i.identity_uid=k.identity_uid"
        " WHERE k.key_id=?", (key_id,)).fetchone()


def _state_error(row: sqlite3.Row | None) -> tuple[int, str, str] | None:
    if row is None:
        return 401, "unknown_key", "unknown key_id"
    if not int(row["identity_enabled"]):
        return 403, "identity_disabled", "service identity is disabled"
    if row["key_state"] != "active":
        return 403, "key_revoked", "api key is revoked"
    return None


def _signature_ok(pepper: bytes, row: sqlite3.Row, auth: AuthHeaders,
                  method: str, target: str, body_sha256: str) -> bool:
    try:
        secret = unseal_secret(pepper, auth.key_id, str(row["secret_sealed"]))
    except Exception:
        return False
    if not secret:
        return False
    return verify_signature(secret, method, target, auth, body_sha256)


def run_server(cfg: GatewayConfig, *, ready_cb: Callable[[int], None] | None = None) -> None:
    srv = GatewayServer(cfg)
    port = srv.server_address[1]
    if ready_cb:
        ready_cb(port)
    sys.stderr.write(f"gateway listening on http://{cfg.host}:{port} db={cfg.db_path}\n")
    sys.stderr.flush()
    try:
        srv.serve_forever(poll_interval=0.1)
    except KeyboardInterrupt:
        pass
    finally:
        srv.server_close()
