"""Shared SQLite access layer.

Design notes
------------
* The database is the single serialisation point.  Every authenticated write
  takes ``BEGIN IMMEDIATE`` before it reads the key/identity state, so the
  state check, the replay insert, the business write and the audit row land in
  one commit.  A revoke that commits first is therefore visible to every
  later state read, and a revoke cannot interleave between a request's check
  and its write, because both are inside the same write transaction.
* Connections are per thread/process, ``isolation_level=None`` (manual
  transactions) and ``check_same_thread=True``.
* Secrets are stored sealed: a keystream derived from a server-side pepper
  (kept in a separate key file, not in the database) is XORed with the secret
  bytes.  Without the pepper file the database alone does not reveal a
  usable key.  A short fingerprint (pepper-keyed hash) is stored for admin
  output; the secret itself is printed only once by ``keys create``.
"""

from __future__ import annotations

import hashlib
import hmac
import os
import sqlite3
import threading
import time
from pathlib import Path
from typing import Any

SCHEMA_VERSION = 1

_BUSY_TIMEOUT_MS = 30_000

# "At most two simultaneously valid keys" is a schema invariant as well as an
# admin check, so a bug in a provisioning path cannot silently create a third.
MAX_ACTIVE_KEYS_PER_IDENTITY = 2

SEAL_CONTEXT = b"gw-seal-v1\x00"
FP_CONTEXT = b"gw-fp-v1\x00"


SCHEMA_SQL = """
CREATE TABLE IF NOT EXISTS meta (
    key   TEXT PRIMARY KEY,
    value TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS tenants (
    tenant_id    TEXT PRIMARY KEY,
    display_name TEXT NOT NULL,
    created_at   TEXT NOT NULL
);

-- A service identity belongs to exactly one tenant.  ``enabled`` is the
-- whole-identity kill switch: 0 disables every key of the identity at once.
CREATE TABLE IF NOT EXISTS service_identities (
    identity_uid TEXT PRIMARY KEY,
    tenant_id    TEXT NOT NULL REFERENCES tenants(tenant_id),
    service_name TEXT NOT NULL,
    enabled      INTEGER NOT NULL DEFAULT 1 CHECK (enabled IN (0,1)),
    created_at   TEXT NOT NULL,
    UNIQUE (tenant_id, service_name)
);

CREATE TABLE IF NOT EXISTS api_keys (
    key_id        TEXT PRIMARY KEY,
    identity_uid  TEXT NOT NULL REFERENCES service_identities(identity_uid),
    secret_sealed TEXT NOT NULL,
    secret_fp     TEXT NOT NULL,
    state         TEXT NOT NULL DEFAULT 'active'
                  CHECK (state IN ('active','revoked')),
    created_at    TEXT NOT NULL,
    revoked_at    TEXT,
    revoked_by    TEXT
);

CREATE INDEX IF NOT EXISTS api_keys_identity ON api_keys(identity_uid, state);

-- Belt and braces: even a buggy provisioning path cannot create a third
-- simultaneously active key for one identity.
CREATE TRIGGER IF NOT EXISTS api_keys_max_active_insert
BEFORE INSERT ON api_keys
WHEN NEW.state = 'active' AND (
    SELECT COUNT(*) FROM api_keys WHERE identity_uid = NEW.identity_uid AND state = 'active'
) >= 2
BEGIN
    SELECT RAISE(ABORT, 'identity already has two active keys');
END;

CREATE TRIGGER IF NOT EXISTS api_keys_max_active_update
BEFORE UPDATE OF state ON api_keys
WHEN NEW.state = 'active' AND OLD.state <> 'active' AND (
    SELECT COUNT(*) FROM api_keys WHERE identity_uid = NEW.identity_uid AND state = 'active'
) >= 2
BEGIN
    SELECT RAISE(ABORT, 'identity already has two active keys');
END;

-- Replay protection.  Uniqueness is (tenant, identity, nonce), NOT key_id:
-- the same nonce signed with the old key and with the new key is still one
-- nonce.  Rows are purged only after their acceptance window has fully
-- expired (see ``Gateway.purge_nonces``).
CREATE TABLE IF NOT EXISTS nonces (
    tenant_id    TEXT NOT NULL,
    identity_uid TEXT NOT NULL,
    nonce        TEXT NOT NULL,
    key_id       TEXT NOT NULL,
    request_ts   INTEGER NOT NULL,
    accepted_at  REAL NOT NULL,
    processed    INTEGER NOT NULL DEFAULT 0,
    PRIMARY KEY (tenant_id, identity_uid, nonce)
);

CREATE INDEX IF NOT EXISTS nonces_expiry ON nonces(accepted_at);

CREATE TABLE IF NOT EXISTS accounts (
    tenant_id  TEXT NOT NULL,
    account_id TEXT NOT NULL,
    counter    INTEGER NOT NULL DEFAULT 0,
    updated_at TEXT NOT NULL,
    PRIMARY KEY (tenant_id, account_id)
);

CREATE TABLE IF NOT EXISTS audit_log (
    seq          INTEGER PRIMARY KEY AUTOINCREMENT,
    at_utc       TEXT NOT NULL,
    at_epoch     REAL NOT NULL,
    event        TEXT NOT NULL,
    tenant_id    TEXT,
    identity_uid TEXT,
    key_id       TEXT,
    account_id   TEXT,
    nonce        TEXT,
    request_ts   INTEGER,
    rc           TEXT,
    detail       TEXT
);

CREATE INDEX IF NOT EXISTS audit_by_identity ON audit_log(tenant_id, identity_uid);
CREATE INDEX IF NOT EXISTS audit_by_event ON audit_log(event);
"""


class GatewayError(Exception):
    """A protocol/authentication failure carrying an HTTP status and code."""

    def __init__(self, status: int, code: str, message: str = "") -> None:
        super().__init__(message or code)
        self.status = status
        self.code = code
        self.message = message or code


class DB:
    """Thin per-thread connection wrapper around one SQLite file."""

    def __init__(self, path: str | os.PathLike[str], *, create: bool = True) -> None:
        self.path = str(path)
        if create and self.path != ":memory:":
            Path(self.path).parent.mkdir(parents=True, exist_ok=True)
        self._local = threading.local()
        self._all: list[sqlite3.Connection] = []
        self._lock = threading.Lock()

    def conn(self) -> sqlite3.Connection:
        c = getattr(self._local, "conn", None)
        if c is None:
            c = sqlite3.connect(self.path, timeout=_BUSY_TIMEOUT_MS / 1000.0,
                                isolation_level=None, check_same_thread=True)
            c.row_factory = sqlite3.Row
            c.execute("PRAGMA journal_mode=WAL")
            c.execute("PRAGMA synchronous=FULL")
            c.execute("PRAGMA foreign_keys=ON")
            c.execute(f"PRAGMA busy_timeout={_BUSY_TIMEOUT_MS}")
            with self._lock:
                self._all.append(c)
            self._local.conn = c
        return c

    def close(self) -> None:
        with self._lock:
            conns, self._all = self._all, []
        for c in conns:
            try:
                c.close()
            except Exception:
                pass
        self._local = threading.local()

    def init_schema(self) -> None:
        c = self.conn()
        c.executescript(SCHEMA_SQL)
        with _Tx(c):
            c.execute("INSERT OR IGNORE INTO meta(key,value) VALUES('schema_version',?)",
                      (str(SCHEMA_VERSION),))

    def schema_version(self) -> int:
        row = self.conn().execute(
            "SELECT value FROM meta WHERE key='schema_version'").fetchone()
        if row is None:
            raise GatewayError(500, "schema_missing", "database is not initialised")
        return int(row["value"])

    def immediate(self) -> "_Tx":
        return _Tx(self.conn())


class _Tx:
    """``BEGIN IMMEDIATE`` ... COMMIT/ROLLBACK context manager."""

    def __init__(self, conn: sqlite3.Connection) -> None:
        self.conn = conn
        self.active = False

    def __enter__(self) -> sqlite3.Connection:
        self.conn.execute("BEGIN IMMEDIATE")
        self.active = True
        return self.conn

    def __exit__(self, exc_type, exc, tb) -> bool:
        if not self.active:
            return False
        self.active = False
        if exc_type is None:
            self.conn.execute("COMMIT")
        else:
            try:
                self.conn.execute("ROLLBACK")
            except Exception:
                pass
        return False


# --------------------------------------------------------------------------
# Secret handling (shared by CLI, gateway and tests)
# --------------------------------------------------------------------------

def load_or_create_pepper(path: str | os.PathLike[str]) -> bytes:
    """Read the server pepper, creating it (0600 where the OS allows) once."""
    p = Path(path)
    if p.exists():
        data = p.read_bytes().strip()
        if len(data) < 32:
            raise SystemExit(f"pepper file {p} is too short")
        return bytes.fromhex(data.decode("ascii"))
    p.parent.mkdir(parents=True, exist_ok=True)
    pepper = os.urandom(32)
    # Create exclusively so two provisioning runs cannot race.
    try:
        fd = os.open(str(p), os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    except FileExistsError:
        return load_or_create_pepper(p)
    with os.fdopen(fd, "w", encoding="ascii") as fh:
        fh.write(pepper.hex())
    return pepper


def _keystream(pepper: bytes, key_id: str) -> bytes:
    return hmac.new(pepper, SEAL_CONTEXT + key_id.encode("utf-8"),
                    hashlib.sha256).digest()


def seal_secret(pepper: bytes, key_id: str, secret: str) -> str:
    raw = secret.encode("utf-8")
    stream = _keystream(pepper, key_id)
    out = bytes(b ^ stream[i % len(stream)] for i, b in enumerate(raw))
    return "seal:v1:" + out.hex()


def unseal_secret(pepper: bytes, key_id: str, sealed: str) -> str:
    if not sealed.startswith("seal:v1:"):
        raise ValueError("unknown secret seal format")
    data = bytes.fromhex(sealed[len("seal:v1:"):])
    stream = _keystream(pepper, key_id)
    raw = bytes(b ^ stream[i % len(stream)] for i, b in enumerate(data))
    return raw.decode("utf-8")


def secret_fingerprint(pepper: bytes, secret: str) -> str:
    return hmac.new(pepper, FP_CONTEXT + secret.encode("utf-8"),
                    hashlib.sha256).hexdigest()[:24]


def generate_secret(nbytes: int = 32) -> str:
    return os.urandom(nbytes).hex()


def generate_key_id(prefix: str = "ak") -> str:
    return f"{prefix}_{os.urandom(8).hex()}"


def utc_iso(epoch: float) -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(epoch))


def audit(conn: sqlite3.Connection, event: str, *, at_epoch: float,
          tenant_id: str | None = None, identity_uid: str | None = None,
          key_id: str | None = None, account_id: str | None = None,
          nonce: str | None = None, request_ts: int | None = None,
          rc: str | None = None, detail: str | None = None) -> None:
    conn.execute(
        "INSERT INTO audit_log(at_utc,at_epoch,event,tenant_id,identity_uid,key_id,"
        "account_id,nonce,request_ts,rc,detail) VALUES(?,?,?,?,?,?,?,?,?,?,?)",
        (utc_iso(at_epoch), at_epoch, event, tenant_id, identity_uid, key_id,
         account_id, nonce, request_ts, rc, detail),
    )


def query_audit(db: DB, *, event: str | None = None, tenant_id: str | None = None,
                limit: int = 1000) -> list[dict[str, Any]]:
    sql = "SELECT * FROM audit_log"
    clauses: list[str] = []
    params: list[Any] = []
    if event:
        clauses.append("event=?")
        params.append(event)
    if tenant_id:
        clauses.append("tenant_id=?")
        params.append(tenant_id)
    if clauses:
        sql += " WHERE " + " AND ".join(clauses)
    sql += " ORDER BY seq LIMIT ?"
    params.append(int(limit))
    return [dict(r) for r in db.conn().execute(sql, params).fetchall()]
