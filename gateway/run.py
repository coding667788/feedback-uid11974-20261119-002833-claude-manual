"""Gateway process entry point.

    python -m gateway.run --db gw.db --pepper-file gw.pepper --port 8080

``--port 0`` binds an ephemeral port; the chosen port is written to the file
given by ``--port-file`` (and printed) so supervisors and tests can find it.
"""

from __future__ import annotations

import argparse
import os
import sys
import time

from .server import GatewayConfig, run_server
from .store import load_or_create_pepper


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description="Local API authentication gateway")
    p.add_argument("--db", default=os.environ.get("GW_DB", "gw.db"))
    p.add_argument("--pepper-file",
                   default=os.environ.get("GW_PEPPER_FILE", "gw.pepper"))
    p.add_argument("--host", default=os.environ.get("GW_HOST", "127.0.0.1"))
    p.add_argument("--port", type=int, default=int(os.environ.get("GW_PORT", "8080")))
    p.add_argument("--port-file", default=os.environ.get("GW_PORT_FILE"))
    p.add_argument("--crash-point", default=os.environ.get("GW_CRASH_POINT"))
    p.add_argument("--crash-account", default=os.environ.get("GW_CRASH_ACCOUNT"))
    p.add_argument("--hold-before-write-ms", type=int,
                   default=int(os.environ.get("GW_HOLD_BEFORE_WRITE_MS", "0")))
    p.add_argument("--hold-before-commit-ms", type=int,
                   default=int(os.environ.get("GW_HOLD_BEFORE_COMMIT_MS", "0")))
    args = p.parse_args(argv)

    pepper = load_or_create_pepper(args.pepper_file)
    clock_env = os.environ.get("GW_FIXED_TIME")
    clock = (lambda: float(clock_env)) if clock_env else time.time
    cfg = GatewayConfig(
        db_path=args.db, pepper=pepper, host=args.host, port=args.port,
        clock=clock, crash_point=args.crash_point,
        crash_account=args.crash_account,
        hold_before_write_ms=args.hold_before_write_ms,
        hold_before_commit_ms=args.hold_before_commit_ms,
    )

    def ready(port: int) -> None:
        if args.port_file:
            tmp = args.port_file + ".tmp"
            with open(tmp, "w", encoding="ascii") as fh:
                fh.write(str(port))
            os.replace(tmp, args.port_file)
        print(f"PORT={port}", flush=True)

    run_server(cfg, ready_cb=ready)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
