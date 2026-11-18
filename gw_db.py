"""SQLite 模式与连接助手。多个网关进程共享同一数据库文件(WAL)。"""
from __future__ import annotations

import sqlite3

SCHEMA = """
CREATE TABLE IF NOT EXISTS identities (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    tenant      TEXT NOT NULL,
    name        TEXT NOT NULL,
    status      TEXT NOT NULL DEFAULT 'active' CHECK (status IN ('active', 'disabled')),
    UNIQUE (tenant, name)
);

CREATE TABLE IF NOT EXISTS keys (
    key_id      TEXT PRIMARY KEY,
    identity_id INTEGER NOT NULL REFERENCES identities(id),
    secret      BLOB NOT NULL,
    status      TEXT NOT NULL DEFAULT 'active' CHECK (status IN ('active', 'revoked')),
    created_at  REAL NOT NULL
);

CREATE TABLE IF NOT EXISTS counters (
    identity_id INTEGER PRIMARY KEY REFERENCES identities(id),
    value       INTEGER NOT NULL DEFAULT 0
);

-- nonce 唯一性范围为 (租户, 服务身份) == identity_id; 与 key_id 无关。
-- expires_at = req_ts + 60, 保留至该签名时间窗口完全过期后才允许清理。
CREATE TABLE IF NOT EXISTS nonces (
    identity_id INTEGER NOT NULL REFERENCES identities(id),
    nonce       TEXT NOT NULL,
    req_ts      INTEGER NOT NULL,
    expires_at  INTEGER NOT NULL,
    PRIMARY KEY (identity_id, nonce)
);

CREATE TABLE IF NOT EXISTS audit (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    server_ts   REAL NOT NULL,
    tenant      TEXT NOT NULL,
    identity    TEXT NOT NULL,
    identity_id INTEGER,
    key_id      TEXT NOT NULL,
    nonce       TEXT NOT NULL,
    action      TEXT NOT NULL,
    result      TEXT NOT NULL,
    target      TEXT NOT NULL
);
"""


def connect(path):
    conn = sqlite3.connect(path, timeout=30)
    conn.execute('PRAGMA journal_mode=WAL')
    conn.execute('PRAGMA busy_timeout=30000')
    conn.execute('PRAGMA foreign_keys=ON')
    return conn


def init_db(path):
    conn = connect(path)
    try:
        conn.executescript(SCHEMA)
        conn.commit()
    finally:
        conn.close()
