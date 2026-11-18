"""Test harness: a real gateway cluster (child processes), real HTTP.

Nothing here fakes the gateway: processes are started with
``python -m gateway.run``, provisioning goes through ``python -m gateway.admin``,
requests go over TCP, and assertions read the SQLite file the gateways used.

Run from the repository root::

    python -m unittest discover -s tests -v
"""

from __future__ import annotations

import json
import os
import shutil
import socket
import sqlite3
import subprocess
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
PY = sys.executable
TMP_ROOT = ROOT / ".runtime-tmp"

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


def _env(extra: dict[str, str] | None = None) -> dict[str, str]:
    e = os.environ.copy()
    e.pop("GW_DB", None)
    e.pop("GW_PEPPER_FILE", None)
    e.pop("GW_CRASH_POINT", None)
    e.pop("GW_CRASH_ACCOUNT", None)
    e.pop("GW_HOLD_BEFORE_WRITE_MS", None)
    e.pop("GW_HOLD_BEFORE_COMMIT_MS", None)
    e.pop("GW_FIXED_TIME", None)
    e["PYTHONPATH"] = str(ROOT)
    if extra:
        e.update(extra)
    return e


def run_cli(args: list[str], *, cwd: Path | None = None,
            env: dict[str, str] | None = None,
            timeout: float = 60.0) -> subprocess.CompletedProcess:
    return subprocess.run(
        [PY, "-m", "gateway.admin", *args],
        cwd=str(cwd or ROOT), env=_env(env), capture_output=True, text=True,
        timeout=timeout)


def wait_port(port: int, timeout: float = 15.0) -> None:
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            with socket.create_connection(("127.0.0.1", port), timeout=0.5):
                return
        except OSError:
            time.sleep(0.05)
    raise TimeoutError(f"gateway on port {port} did not accept connections")


class GwProc:
    def __init__(self, cluster: "Cluster", proc: subprocess.Popen, port: int,
                 log_base: Path) -> None:
        self.cluster = cluster
        self.proc = proc
        self.port = port
        self.base_url = f"http://127.0.0.1:{port}"
        self.stdout_path = log_base.with_suffix(".out")
        self.stderr_path = log_base.with_suffix(".err")

    def wait(self, timeout: float = 20.0) -> int:
        return self.proc.wait(timeout=timeout)

    def alive(self) -> bool:
        return self.proc.poll() is None

    def stop(self) -> None:
        if self.proc.poll() is None:
            self.proc.kill()
        try:
            self.proc.wait(timeout=10)
        except subprocess.TimeoutExpired:
            pass

    def logs(self) -> str:
        out = ""
        for p in (self.stdout_path, self.stderr_path):
            try:
                out += p.read_text(encoding="utf-8", errors="replace")
            except OSError:
                pass
        return out


class Cluster:
    """One DB + pepper + N gateway child processes."""

    def __init__(self, name: str, *, base_dir: Path | None = None) -> None:
        self.name = name
        self.dir = (base_dir or TMP_ROOT) / name
        shutil.rmtree(self.dir, ignore_errors=True)
        self.dir.mkdir(parents=True, exist_ok=True)
        self.db_path = self.dir / "gw.db"
        self.pepper_path = self.dir / "gw.pepper"
        self.secrets_path = self.dir / "secrets.json"
        self.procs: list[GwProc] = []
        self.secrets: dict = {}
        self._n = 0
        self.provision()

    # -- lifecycle --------------------------------------------------------
    def provision(self) -> None:
        cp = run_cli(["--db", str(self.db_path), "--pepper-file", str(self.pepper_path),
                      "provision", "--preset", "demo", "--out", str(self.secrets_path)])
        if cp.returncode != 0:
            raise RuntimeError(f"provision failed: {cp.stdout}\n{cp.stderr}")
        self.secrets = json.loads(self.secrets_path.read_text(encoding="utf-8"))

    def start(self, *, env: dict[str, str] | None = None,
              fixed_time: float | None = None,
              crash_point: str | None = None,
              crash_account: str | None = None,
              hold_before_write_ms: int = 0,
              hold_before_commit_ms: int = 0,
              wait: bool = True) -> GwProc:
        self._n += 1
        log_base = self.dir / f"gw{self._n}"
        port_file = self.dir / f"gw{self._n}.port"
        e = dict(env or {})
        if fixed_time is not None:
            e["GW_FIXED_TIME"] = repr(float(fixed_time))
        if crash_point:
            e["GW_CRASH_POINT"] = crash_point
        if crash_account:
            e["GW_CRASH_ACCOUNT"] = crash_account
        if hold_before_write_ms:
            e["GW_HOLD_BEFORE_WRITE_MS"] = str(hold_before_write_ms)
        if hold_before_commit_ms:
            e["GW_HOLD_BEFORE_COMMIT_MS"] = str(hold_before_commit_ms)
        out = open(log_base.with_suffix(".out"), "wb")
        err = open(log_base.with_suffix(".err"), "wb")
        proc = subprocess.Popen(
            [PY, "-u", "-m", "gateway.run", "--db", str(self.db_path),
             "--pepper-file", str(self.pepper_path), "--port", "0",
             "--port-file", str(port_file)],
            cwd=str(ROOT), env=_env(e), stdout=out, stderr=err,
            stdin=subprocess.DEVNULL)
        gp = GwProc(self, proc, -1, log_base)
        if wait:
            deadline = time.time() + 20.0
            while time.time() < deadline:
                if port_file.exists():
                    txt = port_file.read_text(encoding="ascii").strip()
                    if txt.isdigit():
                        gp.port = int(txt)
                        gp.base_url = f"http://127.0.0.1:{gp.port}"
                        wait_port(gp.port)
                        self.procs.append(gp)
                        return gp
                if proc.poll() is not None:
                    raise RuntimeError(
                        f"gateway exited early rc={proc.returncode}: {gp.logs()}")
                time.sleep(0.05)
            proc.kill()
            raise TimeoutError(f"gateway {self.name} did not become ready: {gp.logs()}")
        self.procs.append(gp)
        return gp

    def stop_all(self) -> None:
        for p in self.procs:
            p.stop()
        self.procs.clear()

    def cleanup(self) -> None:
        self.stop_all()

    # -- DB inspection ----------------------------------------------------
    def connect(self) -> sqlite3.Connection:
        c = sqlite3.connect(str(self.db_path), timeout=30)
        c.row_factory = sqlite3.Row
        return c

    def counter(self, tenant: str, account: str) -> int:
        with self.connect() as c:
            row = c.execute(
                "SELECT counter FROM accounts WHERE tenant_id=? AND account_id=?",
                (tenant, account)).fetchone()
        return -1 if row is None else int(row["counter"])

    def nonce_count(self) -> int:
        with self.connect() as c:
            return int(c.execute("SELECT COUNT(*) FROM nonces").fetchone()[0])

    def nonce_rows(self) -> list[dict]:
        with self.connect() as c:
            return [dict(r) for r in c.execute("SELECT * FROM nonces")]

    def audit(self, **filters) -> list[dict]:
        sql = "SELECT * FROM audit_log"
        clauses, params = [], []
        for k, v in filters.items():
            clauses.append(f"{k}=?")
            params.append(v)
        if clauses:
            sql += " WHERE " + " AND ".join(clauses)
        sql += " ORDER BY seq"
        with self.connect() as c:
            return [dict(r) for r in c.execute(sql, params).fetchall()]

    def accepted(self, **filters) -> list[dict]:
        return self.audit(event="request_accepted", **filters)

    def rejected(self, **filters) -> list[dict]:
        return self.audit(event="request_rejected", **filters)

    # -- secret accessors -------------------------------------------------
    def identity(self, tenant: str, service: str) -> dict:
        for t in self.secrets["tenants"]:
            if t["tenant_id"] != tenant:
                continue
            for s in t["services"]:
                if s["service"] == service:
                    return s
        raise KeyError((tenant, service))

    def key(self, tenant: str, service: str) -> tuple[str, str]:
        s = self.identity(tenant, service)
        return s["key_id"], s["secret"]

    def identity_uid(self, tenant: str, service: str) -> str:
        return self.identity(tenant, service)["identity_uid"]

    def create_key(self, tenant: str, service: str, *,
                   key_id: str | None = None,
                   secret: str | None = None,
                   timeout: float = 60.0) -> tuple[str, str]:
        args = ["--db", str(self.db_path), "--pepper-file", str(self.pepper_path),
                "keys-create", "--tenant", tenant, "--service", service]
        if key_id:
            args += ["--key-id", key_id]
        if secret:
            args += ["--secret", secret]
        cp = run_cli(args, timeout=timeout)
        if cp.returncode != 0:
            raise RuntimeError(f"keys-create failed rc={cp.returncode}: {cp.stderr}")
        rec = json.loads(cp.stdout)
        return rec["key_id"], rec["secret"]

    def revoke(self, key_id: str, *, timeout: float = 60.0) -> float:
        """Revoke via the CLI; returns the wall-clock time the command returned."""
        cp = run_cli(["--db", str(self.db_path), "--pepper-file", str(self.pepper_path),
                      "keys-revoke", "--key-id", key_id], timeout=timeout)
        done = time.time()
        if cp.returncode != 0:
            raise RuntimeError(f"keys-revoke failed rc={cp.returncode}: {cp.stderr}")
        return done

    def set_identity(self, tenant: str, service: str, action: str) -> None:
        cp = run_cli(["--db", str(self.db_path), "--pepper-file", str(self.pepper_path),
                      f"identity-{action}", "--tenant", tenant, "--service", service])
        if cp.returncode != 0:
            raise RuntimeError(f"identity-{action} failed: {cp.stderr}")

    def all_logs(self) -> str:
        return "\n".join(p.logs() for p in self.procs)
