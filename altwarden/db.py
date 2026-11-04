"""SQLite storage. One file, write-ahead logging, and no raw member identifiers in any table.

`identifiers.digest` holds keyed hashes from crypto.Keyring. There is no column for an IP address,
an email address, a cookie value or a Discord token, in this schema or in any JSON stored in it.
"""
from __future__ import annotations

import asyncio
import json
import sqlite3
import time
from pathlib import Path
from typing import Any, Iterable

import aiosqlite

DEPARTED_DAYS = 30  # A server that removes the bot has this long to change its mind

SCHEMA = """
CREATE TABLE IF NOT EXISTS guilds (
    guild_id TEXT PRIMARY KEY,
    settings TEXT NOT NULL,
    setup_done INTEGER NOT NULL DEFAULT 0,
    raid_until REAL NOT NULL DEFAULT 0,
    left_at REAL,
    verify_message_id TEXT,
    honeypot_message_id TEXT,
    created_at REAL NOT NULL,
    updated_at REAL NOT NULL
);
CREATE TABLE IF NOT EXISTS sessions (
    token_hash TEXT PRIMARY KEY,
    guild_id TEXT NOT NULL,
    user_id TEXT NOT NULL,
    state TEXT NOT NULL DEFAULT 'open',
    bypass TEXT NOT NULL DEFAULT '[]',
    bypass_by TEXT,
    created_at REAL NOT NULL,
    expires_at REAL NOT NULL,
    opened_at REAL,
    finished_at REAL,
    auth_state_hash TEXT,
    browser_hash TEXT,
    signed_in_at REAL,
    account TEXT,
    nonce TEXT,
    pow_salt TEXT,
    pow_bits INTEGER NOT NULL DEFAULT 0
);
CREATE INDEX IF NOT EXISTS sessions_member ON sessions (guild_id, user_id);
CREATE INDEX IF NOT EXISTS sessions_expiry ON sessions (expires_at);
CREATE INDEX IF NOT EXISTS sessions_auth_state ON sessions (auth_state_hash);

CREATE TABLE IF NOT EXISTS members (
    guild_id TEXT NOT NULL,
    user_id TEXT NOT NULL,
    username TEXT NOT NULL DEFAULT '',
    avatar TEXT,
    status TEXT NOT NULL DEFAULT 'pending',
    method TEXT,
    verified_at REAL,
    first_verified_at REAL,
    joined_at REAL,
    kick_at REAL,
    fails INTEGER NOT NULL DEFAULT 0,
    last_fail_at REAL,
    limit_reached_at REAL,
    help_thread_id TEXT,
    forget_on_unban INTEGER NOT NULL DEFAULT 0,
    PRIMARY KEY (guild_id, user_id)
);
CREATE INDEX IF NOT EXISTS members_status ON members (guild_id, status);
CREATE INDEX IF NOT EXISTS members_user ON members (user_id);
CREATE INDEX IF NOT EXISTS members_kick ON members (kick_at);

CREATE TABLE IF NOT EXISTS attempts (
    id INTEGER PRIMARY KEY,
    guild_id TEXT NOT NULL,
    user_id TEXT NOT NULL,
    at REAL NOT NULL,
    outcome TEXT NOT NULL,
    check_id TEXT,
    action TEXT,
    mode TEXT,
    seconds REAL,
    bypassed INTEGER NOT NULL DEFAULT 0,
    detail TEXT NOT NULL DEFAULT '{}'
);
CREATE INDEX IF NOT EXISTS attempts_guild_time ON attempts (guild_id, at);
CREATE INDEX IF NOT EXISTS attempts_member ON attempts (guild_id, user_id, at);
CREATE INDEX IF NOT EXISTS attempts_user ON attempts (user_id);

CREATE TABLE IF NOT EXISTS identifiers (
    guild_id TEXT NOT NULL,
    kind TEXT NOT NULL,
    digest TEXT NOT NULL,
    user_id TEXT NOT NULL,
    first_seen REAL NOT NULL,
    last_seen REAL NOT NULL,
    expires_at REAL NOT NULL,
    PRIMARY KEY (guild_id, kind, digest, user_id)
);
CREATE INDEX IF NOT EXISTS identifiers_member ON identifiers (guild_id, user_id);
CREATE INDEX IF NOT EXISTS identifiers_expiry ON identifiers (expires_at);

CREATE TABLE IF NOT EXISTS links (
    guild_id TEXT NOT NULL,
    main_id TEXT NOT NULL,
    alt_id TEXT NOT NULL,
    confidence TEXT NOT NULL,
    score INTEGER NOT NULL,
    methods TEXT NOT NULL,
    at REAL NOT NULL,
    PRIMARY KEY (guild_id, main_id, alt_id)
);
CREATE TABLE IF NOT EXISTS trusted_pairs (
    guild_id TEXT NOT NULL,
    first_id TEXT NOT NULL,
    second_id TEXT NOT NULL,
    by_id TEXT NOT NULL,
    at REAL NOT NULL,
    PRIMARY KEY (guild_id, first_id, second_id)
);
CREATE TABLE IF NOT EXISTS bans (
    guild_id TEXT NOT NULL,
    user_id TEXT NOT NULL,
    at REAL NOT NULL,
    by_altwarden INTEGER NOT NULL DEFAULT 0,
    PRIMARY KEY (guild_id, user_id)
);
CREATE TABLE IF NOT EXISTS appeals (
    id INTEGER PRIMARY KEY,
    guild_id TEXT NOT NULL,
    user_id TEXT NOT NULL,
    check_id TEXT,
    text TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'open',
    created_at REAL NOT NULL,
    decided_by TEXT,
    decided_at REAL,
    note TEXT,
    channel_id TEXT,
    message_id TEXT
);
CREATE INDEX IF NOT EXISTS appeals_guild ON appeals (guild_id, status, created_at);

CREATE TABLE IF NOT EXISTS audit (
    id INTEGER PRIMARY KEY,
    guild_id TEXT NOT NULL,
    at REAL NOT NULL,
    actor_id TEXT,
    actor_name TEXT,
    kind TEXT NOT NULL,
    detail TEXT NOT NULL DEFAULT '{}'
);
CREATE INDEX IF NOT EXISTS audit_guild ON audit (guild_id, at);

CREATE TABLE IF NOT EXISTS web_sessions (
    token_hash TEXT PRIMARY KEY,
    user_id TEXT NOT NULL,
    username TEXT NOT NULL,
    avatar TEXT,
    guilds TEXT NOT NULL DEFAULT '[]',
    csrf TEXT NOT NULL,
    scope TEXT NOT NULL DEFAULT 'dashboard',
    created_at REAL NOT NULL,
    expires_at REAL NOT NULL
);
CREATE TABLE IF NOT EXISTS login_states (
    state_hash TEXT PRIMARY KEY,
    purpose TEXT NOT NULL,
    next_path TEXT NOT NULL DEFAULT '/',
    expires_at REAL NOT NULL
);
CREATE TABLE IF NOT EXISTS command_syncs (
    state_hash TEXT PRIMARY KEY,
    guild_id TEXT NOT NULL,
    user_id TEXT NOT NULL,
    changes TEXT NOT NULL,
    expires_at REAL NOT NULL
);
CREATE TABLE IF NOT EXISTS webhooks (
    id INTEGER PRIMARY KEY,
    guild_id TEXT NOT NULL,
    url TEXT NOT NULL,
    secret TEXT NOT NULL,
    events TEXT NOT NULL DEFAULT '[]',
    created_at REAL NOT NULL,
    last_status INTEGER,
    last_sent_at REAL
);
CREATE TABLE IF NOT EXISTS api_keys (
    key_hash TEXT PRIMARY KEY,
    guild_id TEXT NOT NULL,
    label TEXT NOT NULL,
    created_at REAL NOT NULL,
    last_used_at REAL
);
CREATE TABLE IF NOT EXISTS meta (
    key TEXT PRIMARY KEY,
    value REAL NOT NULL
);
"""


class Database:
    """A thin async wrapper. Queries live here so the rest of the code never builds SQL."""

    def __init__(self, path: str | Path):
        self.path = str(path)
        self.conn: aiosqlite.Connection | None = None

    async def open(self) -> None:
        self.conn = await aiosqlite.connect(self.path)
        self.conn.row_factory = aiosqlite.Row
        await self.conn.execute("PRAGMA journal_mode=WAL")
        await self.conn.execute("PRAGMA synchronous=NORMAL")
        await self.conn.execute("PRAGMA foreign_keys=ON")
        await self.conn.execute("PRAGMA secure_delete=ON")
        await self._add_missing_columns()
        await self.conn.executescript(SCHEMA)
        # A check that was running when the process stopped can't finish now, so hand its link back.
        await self.conn.execute("UPDATE sessions SET state = 'signed_in' WHERE state = 'checking'")
        await self.conn.execute("UPDATE appeals SET status = 'open' WHERE status = 'deciding'")
        # Rows from before this column existed. Without a date they wouldn't count as anyone who verified.
        await self.conn.execute("UPDATE members SET first_verified_at = COALESCE(verified_at, joined_at, ?) WHERE first_verified_at IS NULL "
                                "AND (status = 'verified' OR verified_at IS NOT NULL)", (time.time(),))
        await self.conn.commit()

    async def _add_missing_columns(self) -> None:
        """CREATE TABLE IF NOT EXISTS leaves an older table as it was, so give it whatever the schema has since added."""
        model = sqlite3.connect(":memory:")
        try:
            model.executescript(SCHEMA)
            tables = [row[0] for row in model.execute("SELECT name FROM sqlite_master WHERE type = 'table'")]
            wanted = {table: model.execute(f"PRAGMA table_info({table})").fetchall() for table in tables}
        finally:
            model.close()
        for table, columns in wanted.items():
            present = {row["name"] for row in await self.all(f"PRAGMA table_info({table})")}
            if not present:
                continue
            for _, name, kind, not_null, default, _ in columns:
                if name not in present:
                    await self.conn.execute(f"ALTER TABLE {table} ADD COLUMN {name} {kind}" + (f" DEFAULT {default}" if default is not None else "")
                                            + (" NOT NULL" if not_null else ""))

    async def close(self) -> None:
        if self.conn is not None:
            await self.conn.close()
            self.conn = None

    async def run(self, sql: str, args: Iterable[Any] = ()) -> int:
        cursor = await self.conn.execute(sql, tuple(args))
        await self.conn.commit()
        count = cursor.rowcount
        await cursor.close()
        return count

    async def insert(self, sql: str, args: Iterable[Any] = ()) -> int:
        cursor = await self.conn.execute(sql, tuple(args))
        await self.conn.commit()
        row_id = cursor.lastrowid
        await cursor.close()
        return row_id

    async def one(self, sql: str, args: Iterable[Any] = ()) -> dict | None:
        cursor = await self.conn.execute(sql, tuple(args))
        row = await cursor.fetchone()
        await cursor.close()
        return dict(row) if row is not None else None

    async def all(self, sql: str, args: Iterable[Any] = ()) -> list[dict]:
        cursor = await self.conn.execute(sql, tuple(args))
        rows = await cursor.fetchall()
        await cursor.close()
        return [dict(row) for row in rows]

    async def scalar(self, sql: str, args: Iterable[Any] = ()) -> Any:
        row = await self.one(sql, args)
        return next(iter(row.values())) if row else None

    async def run_many(self, sql: str, rows: list) -> None:
        await self.conn.executemany(sql, rows)
        await self.conn.commit()

    def reader(self) -> sqlite3.Connection:
        """A separate read-only connection, for slow staff pages. Make it on the thread that uses it.

        One connection handles every member's verification, so a long read on it would make them wait.
        """
        connection = sqlite3.connect(f"{Path(self.path).resolve().as_uri()}?mode=ro", uri=True)
        connection.row_factory = sqlite3.Row
        return connection

    async def read_all(self, sql: str, args: Iterable[Any] = ()) -> list[dict]:
        def fetch() -> list[dict]:
            connection = self.reader()
            try:
                return [dict(row) for row in connection.execute(sql, tuple(args))]
            finally:
                connection.close()
        return await asyncio.to_thread(fetch)

    async def get_meta(self, key: str) -> float | None:
        return await self.scalar("SELECT value FROM meta WHERE key = ?", (key,))

    async def set_meta(self, key: str, value: float) -> None:
        await self.run("INSERT INTO meta VALUES (?, ?) ON CONFLICT (key) DO UPDATE SET value = excluded.value", (key, value))

    # --- guilds -----------------------------------------------------------------------------

    async def guild(self, guild_id: str) -> dict | None:
        row = await self.one("SELECT * FROM guilds WHERE guild_id = ?", (guild_id,))
        if row:
            row["settings"] = json.loads(row["settings"])
        return row

    async def save_settings(self, guild_id: str, settings: dict, *, setup_done: bool | None = None) -> None:
        now = time.time()
        await self.run(
            "INSERT INTO guilds (guild_id, settings, setup_done, created_at, updated_at) VALUES (?, ?, ?, ?, ?) "
            "ON CONFLICT (guild_id) DO UPDATE SET settings = excluded.settings, updated_at = excluded.updated_at",
            (guild_id, json.dumps(settings), int(bool(setup_done)), now, now))
        if setup_done is not None:
            await self.run("UPDATE guilds SET setup_done = ? WHERE guild_id = ?", (int(setup_done), guild_id))

    async def set_guild_field(self, guild_id: str, field: str, value: Any) -> None:
        if field not in ("raid_until", "verify_message_id", "honeypot_message_id", "left_at"):
            raise ValueError(field)
        await self.run(f"UPDATE guilds SET {field} = ? WHERE guild_id = ?", (value, guild_id))

    async def mark_departed(self, present: set) -> None:
        """A server that removed the bot while it was offline sent no event, so notice it by its absence."""
        for row in await self.all("SELECT guild_id FROM guilds WHERE left_at IS NULL"):
            if row["guild_id"] not in present:
                await self.set_guild_field(row["guild_id"], "left_at", time.time())

    async def forget_guild(self, guild_id: str) -> None:
        """Remove every row for a server. Used by the uninstall command."""
        for table in ("sessions", "members", "attempts", "identifiers", "links", "trusted_pairs", "bans", "appeals",
                      "audit", "webhooks", "api_keys", "command_syncs", "guilds"):
            await self.run(f"DELETE FROM {table} WHERE guild_id = ?", (guild_id,))

    # --- members ----------------------------------------------------------------------------

    async def member(self, guild_id: str, user_id: str) -> dict | None:
        return await self.one("SELECT * FROM members WHERE guild_id = ? AND user_id = ?", (guild_id, user_id))

    async def touch_member(self, guild_id: str, user_id: str, *, username: str | None = None,
                           avatar: str | None = None) -> None:
        await self.run(
            "INSERT INTO members (guild_id, user_id, username, avatar, joined_at) VALUES (?, ?, ?, ?, ?) "
            "ON CONFLICT (guild_id, user_id) DO UPDATE SET "
            "username = COALESCE(?, username), avatar = COALESCE(?, avatar)",
            (guild_id, user_id, username or "", avatar, time.time(), username, avatar))

    async def update_member(self, guild_id: str, user_id: str, **fields: Any) -> None:
        allowed = {"status", "method", "verified_at", "kick_at", "fails", "last_fail_at", "limit_reached_at",
                   "help_thread_id", "joined_at", "forget_on_unban", "first_verified_at"}
        if not fields or not set(fields) <= allowed:
            raise ValueError(f"Unknown member fields: {set(fields) - allowed}")
        assignments = ", ".join(f"{name} = ?" for name in fields)
        await self.run(f"UPDATE members SET {assignments} WHERE guild_id = ? AND user_id = ?",
                       (*fields.values(), guild_id, user_id))

    async def mark_verified(self, guild_id: str, user_id: str, method: str, *, when: float | None = None) -> None:
        """A member got in. The first time is kept for good, because it decides which of two linked accounts is the main one."""
        moment = when or time.time()
        await self.run("UPDATE members SET status = 'verified', method = ?, verified_at = ?, first_verified_at = COALESCE(first_verified_at, ?), kick_at = NULL, "
                       "fails = 0, limit_reached_at = NULL WHERE guild_id = ? AND user_id = ?", (method, moment, moment, guild_id, user_id))

    # --- identifiers ------------------------------------------------------------------------

    async def store_identifier(self, guild_id: str, user_id: str, kind: str, digest: str, expires_at: float) -> None:
        now = time.time()
        await self.run(
            "INSERT INTO identifiers (guild_id, kind, digest, user_id, first_seen, last_seen, expires_at) "
            "VALUES (?, ?, ?, ?, ?, ?, ?) ON CONFLICT (guild_id, kind, digest, user_id) "
            "DO UPDATE SET last_seen = excluded.last_seen, expires_at = MAX(identifiers.expires_at, excluded.expires_at)",
            (guild_id, kind, digest, user_id, now, now, expires_at))

    async def matches(self, guild_id: str, user_id: str, kind: str, digest: str) -> list[str]:
        rows = await self.all(
            "SELECT user_id FROM identifiers WHERE guild_id = ? AND kind = ? AND digest = ? "
            "AND user_id != ? AND expires_at > ?", (guild_id, kind, digest, user_id, time.time()))
        return [row["user_id"] for row in rows]

    async def digests(self, guild_id: str, user_id: str, kind: str) -> set[str]:
        rows = await self.all("SELECT digest FROM identifiers WHERE guild_id = ? AND user_id = ? AND kind = ? AND expires_at > ?",
                              (guild_id, user_id, kind, time.time()))
        return {row["digest"] for row in rows}

    async def is_trusted_pair(self, guild_id: str, first: str, second: str) -> bool:
        low, high = sorted((first, second), key=int)
        return await self.scalar("SELECT 1 FROM trusted_pairs WHERE guild_id = ? AND first_id = ? AND second_id = ?",
                                 (guild_id, low, high)) is not None

    async def trust_pair(self, guild_id: str, first: str, second: str, by_id: str) -> None:
        low, high = sorted((first, second), key=int)
        await self.run("INSERT OR REPLACE INTO trusted_pairs VALUES (?, ?, ?, ?, ?)",
                       (guild_id, low, high, by_id, time.time()))

    async def is_banned(self, guild_id: str, user_id: str) -> bool:
        return await self.scalar("SELECT 1 FROM bans WHERE guild_id = ? AND user_id = ?", (guild_id, user_id)) is not None

    async def record_ban(self, guild_id: str, user_id: str, *, by_altwarden: bool = False, keep_days: int = 0) -> None:
        now = time.time()
        await self.run("INSERT OR REPLACE INTO bans VALUES (?, ?, ?, ?)", (guild_id, user_id, now, int(by_altwarden)))
        if keep_days:
            # Ban evasion can only be caught while the banned account's digests exist.
            await self.run("UPDATE identifiers SET expires_at = MAX(expires_at, ?) WHERE guild_id = ? AND user_id = ?",
                           (now + keep_days * 86400, guild_id, user_id))

    async def clear_ban(self, guild_id: str, user_id: str) -> None:
        await self.run("DELETE FROM bans WHERE guild_id = ? AND user_id = ?", (guild_id, user_id))

    # --- attempts and audit -----------------------------------------------------------------

    async def add_attempt(self, guild_id: str, user_id: str, outcome: str, *, check_id: str | None = None,
                          action: str | None = None, mode: str | None = None, seconds: float | None = None,
                          bypassed: bool = False, detail: dict | None = None) -> int:
        return await self.insert(
            "INSERT INTO attempts (guild_id, user_id, at, outcome, check_id, action, mode, seconds, bypassed, detail) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (guild_id, user_id, time.time(), outcome, check_id, action, mode, seconds, int(bypassed),
             json.dumps(detail or {})))

    async def add_audit(self, guild_id: str, kind: str, *, actor_id: str | None = None, actor_name: str | None = None,
                        detail: dict | None = None) -> None:
        await self.insert("INSERT INTO audit (guild_id, at, actor_id, actor_name, kind, detail) VALUES (?, ?, ?, ?, ?, ?)",
                          (guild_id, time.time(), actor_id, actor_name, kind, json.dumps(detail or {})))

    # --- retention --------------------------------------------------------------------------

    async def purge_expired(self, settings_by_guild: dict[str, dict]) -> dict:
        """Delete everything past its date. This runs on a timer, so retention needs no one to remember it."""
        now = time.time()
        removed = {
            "identifiers": await self.run("DELETE FROM identifiers WHERE expires_at <= ?", (now,)),
            "sessions": await self.run("DELETE FROM sessions WHERE expires_at <= ?", (now,)),
            "web_sessions": await self.run("DELETE FROM web_sessions WHERE expires_at <= ?", (now,)),
            "login_states": await self.run("DELETE FROM login_states WHERE expires_at <= ?", (now,)),
            "command_syncs": await self.run("DELETE FROM command_syncs WHERE expires_at <= ?", (now,)),
            "attempts": 0,
            "audit": 0,
            "appeals": 0,
            "links": 0,
            "members": 0,
            "bans": 0,
            "departed": 0,
        }
        for row in await self.all("SELECT guild_id FROM guilds WHERE left_at IS NOT NULL AND left_at < ?", (now - DEPARTED_DAYS * 86400,)):
            await self.forget_guild(row["guild_id"])
            settings_by_guild.pop(row["guild_id"], None)
            removed["departed"] += 1
        for guild_id, settings in settings_by_guild.items():
            privacy = settings["privacy"]
            removed["bans"] += await self.run("DELETE FROM bans WHERE guild_id = ? AND at < ?", (guild_id, now - max(privacy["banned_days"], 1) * 86400))
            # Each hash's own date can be late: the setting may have come down since, or a softban may have
            # extended it. So go by when it was last seen, except for accounts that are banned now.
            not_banned = "AND user_id NOT IN (SELECT user_id FROM bans WHERE guild_id = ?)"
            removed["identifiers"] += await self.run(f"DELETE FROM identifiers WHERE guild_id = ? AND kind = 'ip' AND last_seen < ? {not_banned}",
                                                     (guild_id, now - privacy["ip_days"] * 86400, guild_id))
            removed["identifiers"] += await self.run(f"DELETE FROM identifiers WHERE guild_id = ? AND kind != 'ip' AND last_seen < ? {not_banned}",
                                                     (guild_id, now - privacy["identifier_days"] * 86400, guild_id))
            cutoff = now - privacy["attempt_days"] * 86400
            removed["attempts"] += await self.run("DELETE FROM attempts WHERE guild_id = ? AND at < ?", (guild_id, cutoff))
            removed["audit"] += await self.run("DELETE FROM audit WHERE guild_id = ? AND at < ?", (guild_id, cutoff))
            removed["appeals"] += await self.run("DELETE FROM appeals WHERE guild_id = ? AND status NOT IN ('open', 'deciding') AND created_at < ?", (guild_id, cutoff))
            removed["links"] += await self.run("DELETE FROM links WHERE guild_id = ? AND at < ?", (guild_id, now - privacy["identifier_days"] * 86400))
            # A member who never verified and left no recent trace has nothing worth keeping.
            removed["members"] += await self.run(
                "DELETE FROM members WHERE guild_id = ? AND status = 'pending' AND MAX(COALESCE(joined_at, 0), COALESCE(last_fail_at, 0)) < ? "
                "AND kick_at IS NULL AND help_thread_id IS NULL "
                "AND NOT EXISTS (SELECT 1 FROM attempts a WHERE a.guild_id = members.guild_id AND a.user_id = members.user_id) "
                "AND NOT EXISTS (SELECT 1 FROM identifiers i WHERE i.guild_id = members.guild_id AND i.user_id = members.user_id)",
                (guild_id, cutoff))
        return removed
