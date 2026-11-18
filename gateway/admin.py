"""Provisioning and key management (CLI + importable helpers).

Commands::

    python -m gateway.admin --db gw.db --pepper-file gw.pepper init \
        --tenant t1 --service svc1 --account a1
    python -m gateway.admin ... keys-create  --tenant t1 --service svc1
    python -m gateway.admin ... keys-revoke  --key-id ak_...
    python -m gateway.admin ... keys-list    [--tenant t1] [--service svc1]
    python -m gateway.admin ... identity-disable --tenant t1 --service svc1
    python -m gateway.admin ... identity-enable  --tenant t1 --service svc1
    python -m gateway.admin ... status
    python -m gateway.admin ... audit [--event ...]
    python -m gateway.admin ... provision --preset demo --out demo-secrets.json

Every mutating command runs in a single ``BEGIN IMMEDIATE`` transaction, so a
revocation is durably committed before the command returns and every running
gateway process sees it on its next request.  A raw secret is printed exactly
once, by the command that creates the key; ``keys-list``/``status`` only show
a truncated fingerprint.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import time
from typing import Any

from . import store
from .store import (
    DB, GatewayError, MAX_ACTIVE_KEYS_PER_IDENTITY, audit, generate_key_id,
    generate_secret, seal_secret, secret_fingerprint, utc_iso,
)

__all__ = [
    "AdminError", "MAX_ACTIVE_KEYS_PER_IDENTITY", "create_key", "revoke_key",
    "set_identity_enabled", "ensure_tenant", "ensure_identity", "ensure_account",
    "main",
]


class AdminError(Exception):
    pass


# ---------------------------------------------------------------------------
# Core operations (shared by CLI, provisioning and tests)
# ---------------------------------------------------------------------------

def ensure_tenant(conn, tenant_id: str, display_name: str | None = None) -> None:
    conn.execute(
        "INSERT OR IGNORE INTO tenants(tenant_id,display_name,created_at) VALUES(?,?,?)",
        (tenant_id, display_name or tenant_id, utc_iso(time.time())))


def ensure_identity(conn, tenant_id: str, service_name: str) -> str:
    row = conn.execute(
        "SELECT identity_uid FROM service_identities WHERE tenant_id=? AND service_name=?",
        (tenant_id, service_name)).fetchone()
    if row:
        return str(row["identity_uid"])
    uid = f"srv_{os.urandom(8).hex()}"
    conn.execute(
        "INSERT INTO service_identities(identity_uid,tenant_id,service_name,enabled,created_at)"
        " VALUES(?,?,?,1,?)", (uid, tenant_id, service_name, utc_iso(time.time())))
    return uid


def ensure_account(conn, tenant_id: str, account_id: str) -> None:
    conn.execute(
        "INSERT OR IGNORE INTO accounts(tenant_id,account_id,counter,updated_at)"
        " VALUES(?,?,0,?)", (tenant_id, account_id, utc_iso(time.time())))


def create_key(conn, pepper: bytes, identity_uid: str, *,
               key_id: str | None = None, secret: str | None = None,
               enforce_max: bool = True) -> tuple[str, str, str]:
    """Create an active key.  Returns (key_id, secret, fingerprint).

    "At most two simultaneously valid keys per identity" is enforced here.
    Old keys are never auto-revoked: rotating means *enabling* the new key,
    then revoking the old one explicitly, so an operator can always see who
    still holds a live key.
    """
    if enforce_max:
        n = int(conn.execute(
            "SELECT COUNT(*) AS n FROM api_keys WHERE identity_uid=? AND state='active'",
            (identity_uid,)).fetchone()["n"])
        if n >= MAX_ACTIVE_KEYS_PER_IDENTITY:
            raise AdminError(
                f"identity {identity_uid} already has {n} active keys; "
                "revoke one before enabling another")
    key_id = key_id or generate_key_id()
    secret = secret or generate_secret()
    conn.execute(
        "INSERT INTO api_keys(key_id,identity_uid,secret_sealed,secret_fp,state,created_at)"
        " VALUES(?,?,?,?,'active',?)",
        (key_id, identity_uid, seal_secret(pepper, key_id, secret),
         secret_fingerprint(pepper, secret), utc_iso(time.time())))
    return key_id, secret, secret_fingerprint(pepper, secret)


def revoke_key(conn, key_id: str, *, by: str = "admin") -> tuple[str, str]:
    row = conn.execute(
        "SELECT k.key_id, k.state, k.identity_uid, i.tenant_id"
        "  FROM api_keys k JOIN service_identities i ON i.identity_uid=k.identity_uid"
        " WHERE k.key_id=?", (key_id,)).fetchone()
    if row is None:
        raise AdminError(f"unknown key_id {key_id}")
    if row["state"] == "revoked":
        return str(row["identity_uid"]), "already_revoked"
    conn.execute("UPDATE api_keys SET state='revoked', revoked_at=?, revoked_by=?"
                 " WHERE key_id=?", (utc_iso(time.time()), by, key_id))
    audit(conn, "key_revoked", at_epoch=time.time(), tenant_id=row["tenant_id"],
          identity_uid=row["identity_uid"], key_id=key_id, rc="ok",
          detail=f"by={by}")
    return str(row["identity_uid"]), "revoked"


def set_identity_enabled(conn, *, tenant_id: str, service_name: str,
                         enabled: bool, by: str = "admin") -> str:
    row = conn.execute(
        "SELECT identity_uid FROM service_identities WHERE tenant_id=? AND service_name=?",
        (tenant_id, service_name)).fetchone()
    if row is None:
        raise AdminError(f"unknown service identity {tenant_id}/{service_name}")
    uid = str(row["identity_uid"])
    conn.execute("UPDATE service_identities SET enabled=? WHERE identity_uid=?",
                 (1 if enabled else 0, uid))
    audit(conn, "identity_enabled" if enabled else "identity_disabled",
          at_epoch=time.time(), tenant_id=tenant_id, identity_uid=uid,
          rc="ok", detail=f"by={by}")
    return uid


# ---------------------------------------------------------------------------
# Provisioning
# ---------------------------------------------------------------------------

DEMO_PRESET = {
    "tenants": [
        {"tenant_id": "tenant-a", "services": [
            {"service": "ingest", "accounts": ["acct-1", "acct-2"]},
            {"service": "billing", "accounts": ["acct-1"]},
        ]},
        {"tenant_id": "tenant-b", "services": [
            {"service": "ingest", "accounts": ["acct-1"]},
        ]},
    ]
}


def provision(db: DB, pepper: bytes, preset: dict[str, Any]) -> dict[str, Any]:
    """Seed tenants/identities/accounts and one key each, in one transaction."""
    result: dict[str, Any] = {"tenants": []}
    with db.immediate() as conn:
        for t in preset["tenants"]:
            tenant_id = t["tenant_id"]
            ensure_tenant(conn, tenant_id, t.get("display_name"))
            t_out = {"tenant_id": tenant_id, "services": []}
            for s in t["services"]:
                uid = ensure_identity(conn, tenant_id, s["service"])
                for acct in s.get("accounts", []):
                    ensure_account(conn, tenant_id, acct)
                key_id, secret, fp = create_key(conn, pepper, uid)
                t_out["services"].append({
                    "service": s["service"], "identity_uid": uid,
                    "accounts": list(s.get("accounts", [])),
                    "key_id": key_id, "secret": secret, "fingerprint": fp,
                })
            result["tenants"].append(t_out)
    return result


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def _db(args: argparse.Namespace) -> DB:
    db = DB(args.db)
    db.init_schema()
    return db


def _pepper(args: argparse.Namespace) -> bytes:
    return store.load_or_create_pepper(args.pepper_file)


def _print(obj: Any) -> None:
    print(json.dumps(obj, indent=2, sort_keys=True))


def _key_record(tenant: str, service: str, key_id: str, secret: str, fp: str) -> dict:
    return {"tenant": tenant, "service": service, "key_id": key_id,
            "secret": secret, "fingerprint": fp,
            "warning": "the secret is shown once; store it in a client secret file"}


def cmd_init(args: argparse.Namespace) -> int:
    db, pepper = _db(args), _pepper(args)
    with db.immediate() as conn:
        ensure_tenant(conn, args.tenant)
        uid = ensure_identity(conn, args.tenant, args.service)
        ensure_account(conn, args.tenant, args.account)
        key_id, secret, fp = create_key(conn, pepper, uid)
    _print(_key_record(args.tenant, args.service, key_id, secret, fp))
    return 0


def cmd_provision(args: argparse.Namespace) -> int:
    db, pepper = _db(args), _pepper(args)
    if args.preset != "demo":
        raise AdminError(f"unknown preset {args.preset!r} (only 'demo')")
    result = provision(db, pepper, DEMO_PRESET)
    if args.out:
        # 0600 where the OS supports it: this file contains live secrets.
        fd = os.open(args.out, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            json.dump(result, fh, indent=2)
        print(json.dumps({"written": args.out,
                          "tenants": [t["tenant_id"] for t in result["tenants"]]}))
    else:
        _print(result)
    return 0


def cmd_keys_create(args: argparse.Namespace) -> int:
    db, pepper = _db(args), _pepper(args)
    with db.immediate() as conn:
        row = conn.execute(
            "SELECT identity_uid FROM service_identities WHERE tenant_id=? AND service_name=?",
            (args.tenant, args.service)).fetchone()
        if row is None:
            raise AdminError(f"unknown service identity {args.tenant}/{args.service}")
        key_id, secret, fp = create_key(conn, pepper, str(row["identity_uid"]),
                                        key_id=args.key_id, secret=args.secret)
        audit(conn, "key_created", at_epoch=time.time(), tenant_id=args.tenant,
              identity_uid=row["identity_uid"], key_id=key_id, rc="ok",
              detail="by=cli")
    _print(_key_record(args.tenant, args.service, key_id, secret, fp))
    return 0


def cmd_keys_revoke(args: argparse.Namespace) -> int:
    db = _db(args)
    with db.immediate() as conn:
        identity_uid, result = revoke_key(conn, args.key_id, by="cli")
    _print({"key_id": args.key_id, "identity_uid": identity_uid, "result": result})
    return 0


def cmd_keys_list(args: argparse.Namespace) -> int:
    db = _db(args)
    sql = ("SELECT k.key_id, k.identity_uid, i.tenant_id, i.service_name,"
           "       k.state, k.secret_fp, k.created_at, k.revoked_at"
           "  FROM api_keys k JOIN service_identities i ON i.identity_uid=k.identity_uid")
    clauses: list[str] = []
    params: list[Any] = []
    if args.tenant:
        clauses.append("i.tenant_id=?")
        params.append(args.tenant)
    if args.service:
        clauses.append("i.service_name=?")
        params.append(args.service)
    if clauses:
        sql += " WHERE " + " AND ".join(clauses)
    sql += " ORDER BY i.tenant_id, i.service_name, k.created_at"
    _print([dict(r) for r in db.conn().execute(sql, params).fetchall()])
    return 0


def cmd_identity_set(args: argparse.Namespace) -> int:
    db = _db(args)
    enable = args.action == "enable"
    with db.immediate() as conn:
        uid = set_identity_enabled(conn, tenant_id=args.tenant,
                                   service_name=args.service, enabled=enable,
                                   by="cli")
    _print({"identity_uid": uid, "enabled": enable})
    return 0


def cmd_status(args: argparse.Namespace) -> int:
    db = _db(args)
    rows = db.conn().execute(
        "SELECT i.tenant_id, i.service_name, i.identity_uid, i.enabled,"
        "       SUM(CASE WHEN k.state='active' THEN 1 ELSE 0 END) AS active_keys,"
        "       COUNT(k.key_id) AS total_keys"
        "  FROM service_identities i"
        "  LEFT JOIN api_keys k ON k.identity_uid=i.identity_uid"
        " GROUP BY i.identity_uid ORDER BY i.tenant_id, i.service_name").fetchall()
    _print([dict(r) for r in rows])
    return 0


def cmd_audit(args: argparse.Namespace) -> int:
    db = _db(args)
    _print(store.query_audit(db, event=args.event, tenant_id=args.tenant,
                            limit=args.limit))
    return 0


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="gateway.admin",
                                description="Local API auth gateway administration")
    p.add_argument("--db", default=os.environ.get("GW_DB", "gw.db"))
    p.add_argument("--pepper-file",
                   default=os.environ.get("GW_PEPPER_FILE", "gw.pepper"))
    sub = p.add_subparsers(dest="cmd", required=True)

    q = sub.add_parser("init", help="create tenant/service/account and a first key")
    q.add_argument("--tenant", required=True)
    q.add_argument("--service", required=True)
    q.add_argument("--account", required=True)
    q.set_defaults(func=cmd_init)

    q = sub.add_parser("provision", help="seed the demo preset")
    q.add_argument("--preset", default="demo")
    q.add_argument("--out", help="write secrets to this JSON file (0600)")
    q.set_defaults(func=cmd_provision)

    q = sub.add_parser("keys-create", aliases=["key-create"],
                       help="enable an additional key for an identity (max 2 active)")
    q.add_argument("--tenant", required=True)
    q.add_argument("--service", required=True)
    q.add_argument("--key-id")
    q.add_argument("--secret", help="operator-supplied secret (testing only)")
    q.set_defaults(func=cmd_keys_create)

    q = sub.add_parser("keys-revoke", aliases=["key-revoke"],
                       help="revoke one key immediately (durable before return)")
    q.add_argument("--key-id", required=True)
    q.set_defaults(func=cmd_keys_revoke)

    q = sub.add_parser("keys-list", aliases=["key-list"],
                       help="list keys and fingerprints (never secrets)")
    q.add_argument("--tenant")
    q.add_argument("--service")
    q.set_defaults(func=cmd_keys_list)

    for action in ("disable", "enable"):
        q = sub.add_parser(f"identity-{action}",
                           help=f"{action} a whole service identity")
        q.add_argument("--tenant", required=True)
        q.add_argument("--service", required=True)
        q.set_defaults(func=cmd_identity_set, action=action)

    q = sub.add_parser("status", help="summarise identities and key counts")
    q.set_defaults(func=cmd_status)

    q = sub.add_parser("audit", help="print recent audit rows")
    q.add_argument("--event")
    q.add_argument("--tenant")
    q.add_argument("--limit", type=int, default=100)
    q.set_defaults(func=cmd_audit)
    return p


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        return args.func(args)
    except (AdminError, GatewayError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
