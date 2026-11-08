"""SQLite storage, encrypted with SQLCipher. One file, with write-ahead logging.

The file and its log are unreadable without a key derived from the master key, and that key is never stored.
Inside, Discord IDs and usernames are stored as they are. `identifiers.digest` holds keyed hashes from
crypto.Keyring. There is no column for an IP address, an email address, a cookie value or a Discord
token, in this schema or in any JSON stored in it.
"""
from __future__ import annotations

import asyncio
import json
import re
import time
from pathlib import Path
from typing import Any, Iterable

import aiosqlite
from sqlcipher3 import dbapi2 as cipher

from .crypto import SEALED_PREFIX, is_sealed

DEPARTED_DAYS = 30  # A server that removes the bot has this long to change its mind
WAL_LIMIT_BYTES = 4 * 1024 * 1024  # what the log may keep on disk after a checkpoint, about one automatic checkpoint's worth
# Per member per kind, newest kept. A device value says only the kind of machine, and a person has few, so one account can't collect many to plant.
IDENTIFIER_CAPS = {"ip": 20, "device": 3, "os": 5, "browser": 5}
IDENTIFIER_CAP = 10
MATCH_LIMIT = 200  # accounts per matching value. Ones that got in or were banned sort first, so a pile of failed attempts can't push them out
LOOKUP_CHUNK = 400  # IDs per query, under SQLite's oldest limit on bound values even when a query lists them twice
# When each table's row was last relevant, for rows whose server has no record left.
ORPHAN_AGE = {"sessions": "created_at", "members": "COALESCE(joined_at, last_fail_at, verified_at, 0)", "attempts": "at", "identifiers": "last_seen",
              "links": "at", "trusted_pairs": "at", "bans": "at", "appeals": "created_at", "audit": "at", "webhooks": "created_at",
              "lookup_keys": "saved_at", "api_keys": "created_at"}
# Values the bot has to read back, so they're encrypted rather than hashed: table, its key, and the column.
SEALED_COLUMNS = (("lookup_keys", "guild_id", "lookup_key"), ("webhooks", "id", "secret"), ("webhooks", "id", "url"))

KEEP = object()  # "not given", where None is a real value

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
    pow_bits INTEGER NOT NULL DEFAULT 0,
    fixes TEXT
);
CREATE INDEX IF NOT EXISTS sessions_member ON sessions (guild_id, user_id);
CREATE INDEX IF NOT EXISTS sessions_expiry ON sessions (expires_at);

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
    limit_held INTEGER NOT NULL DEFAULT 0,
    help_thread_id TEXT,
    help_reminded_at REAL,
    forget_on_unban INTEGER NOT NULL DEFAULT 0,
    kick_warn_at REAL,
    PRIMARY KEY (guild_id, user_id)
);
CREATE INDEX IF NOT EXISTS members_status ON members (guild_id, status);
CREATE INDEX IF NOT EXISTS members_user ON members (user_id);
CREATE INDEX IF NOT EXISTS members_kick ON members (kick_at);
CREATE INDEX IF NOT EXISTS members_kick_warn ON members (kick_warn_at) WHERE kick_warn_at IS NOT NULL;
CREATE INDEX IF NOT EXISTS members_limit_reached ON members (limit_reached_at) WHERE limit_reached_at IS NOT NULL;

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
CREATE UNIQUE INDEX IF NOT EXISTS appeals_one_waiting ON appeals (guild_id, user_id) WHERE status IN ('open', 'deciding');

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
CREATE TABLE IF NOT EXISTS lookup_keys (
    guild_id TEXT PRIMARY KEY,
    lookup_key TEXT NOT NULL,
    saved_at REAL NOT NULL
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


CIPHER_COMPATIBILITY = 4  # the file format, stated so a newer library's defaults can't change what it expects to read


class DatabaseKeyError(RuntimeError):
    """The key doesn't open this file. No key is ever in the message."""


def open_encrypted(target: str, key: str, **options) -> cipher.Connection:
    """A connection to the encrypted database, given the key before anything else can touch the file.

    The key goes in raw, so opening a connection costs no password stretching. Staff pages open one for each read.
    """
    connection = cipher.connect(target, **options)
    try:
        connection.execute(f"PRAGMA key = \"x'{key}'\"").fetchall()
        connection.execute(f"PRAGMA cipher_compatibility = {CIPHER_COMPATIBILITY}").fetchall()
        connection.execute("SELECT count(*) FROM sqlite_master").fetchone()  # the first read is when a wrong key shows
    except cipher.DatabaseError as error:
        connection.close()
        if "not a database" in str(error):
            raise DatabaseKeyError("This MASTER_KEY can't open the database. A plain database from before version 1.3 needs converting once: "
                                   "stop the bot and run python -m altwarden.encrypt_database. Otherwise it was made with another key, so put that key back.") from None
        raise
    return connection


def integrity_problems(connection: cipher.Connection) -> list[str]:
    """What SQLCipher and SQLite each find wrong with a database. An empty list means they found nothing."""
    problems = [row[0] for row in connection.execute("PRAGMA cipher_integrity_check")]
    if problems:  # SQLite's own check can't read a page that fails its authentication code, and stops with an error
        return problems
    return [row[0] for row in connection.execute("PRAGMA integrity_check") if row[0] != "ok"]


class Database:
    """A thin async wrapper over one connection, holding the queries several places share. Others pass their own bound SQL to `run`, `one` and `all`."""

    def __init__(self, path: str | Path, key: str):
        if not re.fullmatch(r"[0-9a-f]{64}", key):  # it goes into a PRAGMA, which can't take a bound value
            raise ValueError("The database key has to be 64 lowercase hex digits. Use Keyring.database_key.")
        self.path = str(path)
        self._key = key
        self.conn: aiosqlite.Connection | None = None
        self._checkpointing = asyncio.Lock()

    async def open(self) -> None:
        # aiosqlite only knows how to open stock SQLite, so it gets a connector, which it runs on its own thread.
        self.conn = await aiosqlite.Connection(lambda: open_encrypted(self.path, self._key), 64)
        self.conn.row_factory = cipher.Row
        await self.conn.execute("PRAGMA journal_mode=WAL")
        await self.conn.execute("PRAGMA synchronous=NORMAL")
        await self.conn.execute("PRAGMA foreign_keys=ON")
        await self.conn.execute("PRAGMA secure_delete=ON")
        await self.conn.execute(f"PRAGMA journal_size_limit={WAL_LIMIT_BYTES}")
        await self._add_missing_columns()
        await self._prepare_older_tables()
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
        model = cipher.connect(":memory:")
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

    async def _prepare_older_tables(self) -> None:
        """Clear what an older database holds that the schema no longer allows."""
        await self.conn.execute("DROP INDEX IF EXISTS sessions_auth_state")  # no query ever filtered on it
        if await self.scalar("SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = 'appeals'"):
            # Two submits at once could each open an appeal before only one could wait. The first one's card is what staff saw first.
            await self.conn.execute("DELETE FROM appeals WHERE status IN ('open', 'deciding') AND id NOT IN "
                                    "(SELECT MIN(id) FROM appeals WHERE status IN ('open', 'deciding') GROUP BY guild_id, user_id)")

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

    def reader(self) -> cipher.Connection:
        """A separate read-only connection, for slow staff pages. Make it on the thread that uses it.

        One connection handles every member's verification, so a long read on it would make them wait.
        """
        connection = open_encrypted(f"{Path(self.path).resolve().as_uri()}?mode=ro", self._key, uri=True)
        connection.row_factory = cipher.Row
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
        await self.run("INSERT INTO meta (key, value) VALUES (?, ?) ON CONFLICT (key) DO UPDATE SET value = excluded.value", (key, value))

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
        """Remove every row for a server, and the copies the write-ahead log still holds. Used by the uninstall command."""
        await self._delete_guild(guild_id)
        await self.checkpoint()

    async def _delete_guild(self, guild_id: str) -> None:
        for table in ("sessions", "members", "attempts", "identifiers", "links", "trusted_pairs", "bans", "appeals",
                      "audit", "webhooks", "api_keys", "lookup_keys", "command_syncs", "guilds"):
            await self.run(f"DELETE FROM {table} WHERE guild_id = ?", (guild_id,))

    async def checkpoint(self) -> bool:
        """Empty the write-ahead log. secure_delete only clears the main file, so deleted values stay readable in the log until this.

        Returns False if a reader or an unfinished write held it up. The hourly purge runs it again. Every query shares one
        worker thread, so waiting out the busy timeout here would stall the whole bot. It gets no wait at all, and only this
        connection writes, so nothing that slips in before the timeout comes back can find the database busy. The statement
        runs and finishes as one job on that thread, because a commit from anyone else while it's open is refused.
        """
        async with self._checkpointing:  # a second one would read the zero as the value to put back
            previous = await self.scalar("PRAGMA busy_timeout")
            await self.scalar("PRAGMA busy_timeout = 0")
            try:
                await self.conn.commit()
                rows = await self.conn.execute_fetchall("PRAGMA wal_checkpoint(TRUNCATE)")
            except cipher.OperationalError:
                return False
            finally:
                await self.scalar(f"PRAGMA busy_timeout = {int(previous)}")
            return rows[0][0] == 0

    async def lookup_key(self, guild_id: str) -> str | None:
        """The stored value, sealed by the service. Anything that uses the key goes through Service.lookup_key."""
        return await self.scalar("SELECT lookup_key FROM lookup_keys WHERE guild_id = ?", (guild_id,))

    async def unsealed_secrets(self) -> list[dict]:
        """Stored secrets still in plain text: where each one lives, for `store_sealed`, and which server's key seals it."""
        found = []
        for table, key, column in SEALED_COLUMNS:
            for row in await self.all(f"SELECT {key} AS row_key, guild_id, {column} AS value FROM {table} WHERE {column} NOT LIKE ?", (f"{SEALED_PREFIX}%",)):
                found.append({"table": table, "column": column, **row})
        return found

    async def store_sealed(self, table: str, column: str, row_key: Any, value: str, *, plain: str) -> bool:
        """Swap one plain value for its sealed form, only if the row still holds that plain value."""
        keys = {(name, field): key for name, key, field in SEALED_COLUMNS}
        if (table, column) not in keys or not is_sealed(value):
            raise ValueError(f"Not a sealed column or value: {table}.{column}")
        return await self.run(f"UPDATE {table} SET {column} = ? WHERE {keys[table, column]} = ? AND {column} = ?", (value, row_key, plain)) > 0

    async def set_lookup_key(self, guild_id: str, key: str | None) -> None:
        if key is None:
            await self.run("DELETE FROM lookup_keys WHERE guild_id = ?", (guild_id,))
            await self.checkpoint()
            return
        await self.run("INSERT INTO lookup_keys (guild_id, lookup_key, saved_at) VALUES (?, ?, ?) "
                       "ON CONFLICT (guild_id) DO UPDATE SET lookup_key = excluded.lookup_key, saved_at = excluded.saved_at",
                       (guild_id, key, time.time()))

    # --- members ----------------------------------------------------------------------------

    async def member(self, guild_id: str, user_id: str) -> dict | None:
        return await self.one("SELECT * FROM members WHERE guild_id = ? AND user_id = ?", (guild_id, user_id))

    async def touch_member(self, guild_id: str, user_id: str, *, username: str | None = None,
                           avatar: str | None | object = KEEP) -> None:
        """Make sure a member has a row. An avatar of None means they removed their picture. Leave it out when it isn't known."""
        given = avatar is not KEEP
        picture = avatar if given else None
        await self.run(
            "INSERT INTO members (guild_id, user_id, username, avatar, joined_at) VALUES (?, ?, ?, ?, ?) "
            "ON CONFLICT (guild_id, user_id) DO UPDATE SET "
            "username = COALESCE(?, username), avatar = CASE WHEN ? THEN ? ELSE avatar END",
            (guild_id, user_id, username or "", picture, time.time(), username, given, picture))

    async def update_member(self, guild_id: str, user_id: str, **fields: Any) -> None:
        allowed = {"status", "method", "verified_at", "kick_at", "kick_warn_at", "fails", "last_fail_at", "limit_reached_at",
                   "help_thread_id", "help_reminded_at", "joined_at", "forget_on_unban", "first_verified_at"}
        if not fields or not set(fields) <= allowed:
            raise ValueError(f"Unknown member fields: {set(fields) - allowed}")
        assignments = ", ".join(f"{name} = ?" for name in fields)
        await self.run(f"UPDATE members SET {assignments} WHERE guild_id = ? AND user_id = ?",
                       (*fields.values(), guild_id, user_id))

    async def mark_verified(self, guild_id: str, user_id: str, method: str, *, when: float | None = None) -> None:
        """A member got in. The first time is kept for good, because it decides which of two linked accounts is the main one."""
        moment = when or time.time()
        await self.run("UPDATE members SET status = 'verified', method = ?, verified_at = ?, first_verified_at = COALESCE(first_verified_at, ?), kick_at = NULL, kick_warn_at = NULL, "
                       "fails = 0, limit_reached_at = NULL WHERE guild_id = ? AND user_id = ?", (method, moment, moment, guild_id, user_id))

    # --- identifiers ------------------------------------------------------------------------

    async def store_identifier(self, guild_id: str, user_id: str, kind: str, digest: str, expires_at: float) -> None:
        now = time.time()
        await self.run(
            "INSERT INTO identifiers (guild_id, kind, digest, user_id, first_seen, last_seen, expires_at) "
            "VALUES (?, ?, ?, ?, ?, ?, ?) ON CONFLICT (guild_id, kind, digest, user_id) "
            "DO UPDATE SET last_seen = excluded.last_seen, expires_at = MAX(identifiers.expires_at, excluded.expires_at)",
            (guild_id, kind, digest, user_id, now, now, expires_at))
        # The client states most of these, so one account could otherwise store as many as it has attempts.
        await self.run(
            "DELETE FROM identifiers WHERE guild_id = ?1 AND user_id = ?2 AND kind = ?3 AND digest NOT IN "
            "(SELECT digest FROM identifiers WHERE guild_id = ?1 AND user_id = ?2 AND kind = ?3 ORDER BY last_seen DESC, rowid DESC LIMIT ?4)",
            (guild_id, user_id, kind, IDENTIFIER_CAPS.get(kind, IDENTIFIER_CAP)))

    async def matches(self, guild_id: str, user_id: str, kind: str, digest: str) -> list[str]:
        """Other accounts holding this value, the ones that matter most first: banned, then got in, then most recently seen."""
        rows = await self.all(
            "SELECT i.user_id FROM identifiers i "
            "LEFT JOIN members m ON m.guild_id = i.guild_id AND m.user_id = i.user_id "
            "LEFT JOIN bans b ON b.guild_id = i.guild_id AND b.user_id = i.user_id "
            "WHERE i.guild_id = ? AND i.kind = ? AND i.digest = ? AND i.user_id != ? AND i.expires_at > ? "
            "ORDER BY b.user_id IS NOT NULL DESC, COALESCE(m.first_verified_at IS NOT NULL OR m.status = 'approved', 0) DESC, i.last_seen DESC LIMIT ?",
            (guild_id, kind, digest, user_id, time.time(), MATCH_LIMIT))
        return [row["user_id"] for row in rows]

    async def link_facts(self, guild_id: str, user_id: str, others: list[str]) -> dict[str, dict]:
        """For each other account: whether it's banned, whether it got in, and whether staff trust it alongside this one."""
        facts = {other: {"banned": False, "verified": False, "trusted": False} for other in others}
        for start in range(0, len(others), LOOKUP_CHUNK):
            part = others[start:start + LOOKUP_CHUNK]
            marks = ",".join("?" * len(part))
            for row in await self.all(f"SELECT user_id FROM bans WHERE guild_id = ? AND user_id IN ({marks})", (guild_id, *part)):
                facts[row["user_id"]]["banned"] = True
            for row in await self.all(f"SELECT user_id FROM members WHERE guild_id = ? AND user_id IN ({marks}) AND (first_verified_at IS NOT NULL OR status = 'approved')",
                                      (guild_id, *part)):
                facts[row["user_id"]]["verified"] = True
            for row in await self.all(f"SELECT first_id, second_id FROM trusted_pairs WHERE guild_id = ? AND "
                                      f"((first_id = ? AND second_id IN ({marks})) OR (second_id = ? AND first_id IN ({marks})))",
                                      (guild_id, user_id, *part, user_id, *part)):
                facts[row["second_id"] if row["first_id"] == user_id else row["first_id"]]["trusted"] = True
        return facts

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
        await self.run("INSERT OR REPLACE INTO trusted_pairs (guild_id, first_id, second_id, by_id, at) VALUES (?, ?, ?, ?, ?)",
                       (guild_id, low, high, by_id, time.time()))

    async def is_banned(self, guild_id: str, user_id: str) -> bool:
        return await self.scalar("SELECT 1 FROM bans WHERE guild_id = ? AND user_id = ?", (guild_id, user_id)) is not None

    async def record_ban(self, guild_id: str, user_id: str, *, by_altwarden: bool = False, keep_days: int = 0) -> None:
        now = time.time()
        # Discord's ban event follows AltWarden's own ban, and mustn't wipe who did it or restart the ban's clock.
        await self.run("INSERT INTO bans (guild_id, user_id, at, by_altwarden) VALUES (?, ?, ?, ?) ON CONFLICT (guild_id, user_id) "
                       "DO UPDATE SET by_altwarden = MAX(bans.by_altwarden, excluded.by_altwarden)", (guild_id, user_id, now, int(by_altwarden)))
        if keep_days:
            # Ban evasion can only be caught while the banned account's digests exist. An address moves on to someone else,
            # and a banned planter could otherwise stop a stranger on it for years, so an address keeps its own date.
            await self.run("UPDATE identifiers SET expires_at = MAX(expires_at, ?) WHERE guild_id = ? AND user_id = ? AND kind != 'ip'",
                           (now + keep_days * 86400, guild_id, user_id))

    async def clear_ban(self, guild_id: str, user_id: str) -> None:
        await self.run("DELETE FROM bans WHERE guild_id = ? AND user_id = ?", (guild_id, user_id))

    # --- appeals ----------------------------------------------------------------------------

    async def open_appeal(self, guild_id: str, user_id: str, check_id: str | None, text: str) -> int | None:
        """Open an appeal, or return None if this member already has one waiting. The database decides, so two submits at once open one."""
        cursor = await self.conn.execute("INSERT INTO appeals (guild_id, user_id, check_id, text, created_at) VALUES (?, ?, ?, ?, ?) ON CONFLICT DO NOTHING",
                                         (guild_id, user_id, check_id, text, time.time()))
        await self.conn.commit()
        opened = cursor.lastrowid if cursor.rowcount > 0 else None
        await cursor.close()
        return opened

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
            "orphans": 0,
        }
        for row in await self.all("SELECT guild_id FROM guilds WHERE left_at IS NOT NULL AND left_at < ?", (now - DEPARTED_DAYS * 86400,)):
            await self._delete_guild(row["guild_id"])
            settings_by_guild.pop(row["guild_id"], None)
            removed["departed"] += 1
        for guild_id, settings in settings_by_guild.items():
            privacy = settings["privacy"]
            removed["bans"] += await self.run("DELETE FROM bans WHERE guild_id = ? AND at < ?", (guild_id, now - max(privacy["banned_days"], 1) * 86400))
            # Each hash's own date can be late: the setting may have come down since, or a softban may have
            # extended it. So go by when it was last seen. A ban keeps every kind but the address.
            not_banned = "AND user_id NOT IN (SELECT user_id FROM bans WHERE guild_id = ?)"
            removed["identifiers"] += await self.run("DELETE FROM identifiers WHERE guild_id = ? AND kind = 'ip' AND last_seen < ?",
                                                     (guild_id, now - privacy["ip_days"] * 86400))
            removed["identifiers"] += await self.run(f"DELETE FROM identifiers WHERE guild_id = ? AND kind != 'ip' AND last_seen < ? {not_banned}",
                                                     (guild_id, now - privacy["identifier_days"] * 86400, guild_id))
            cutoff = now - privacy["attempt_days"] * 86400
            removed["attempts"] += await self.run("DELETE FROM attempts WHERE guild_id = ? AND at < ?", (guild_id, cutoff))
            removed["audit"] += await self.run("DELETE FROM audit WHERE guild_id = ? AND at < ?", (guild_id, cutoff))
            removed["appeals"] += await self.run("DELETE FROM appeals WHERE guild_id = ? AND status != 'deciding' AND created_at < ?", (guild_id, cutoff))
            removed["links"] += await self.run("DELETE FROM links WHERE guild_id = ? AND at < ?", (guild_id, now - privacy["identifier_days"] * 86400))
            # A member who never verified and left no recent trace has nothing worth keeping. Someone who once got in stays
            # pending after a later failure or a rejoin, and that first date still decides who the main account is. A limit
            # reached is kept too while the limit is on, because a row gone would hand back attempts that never return.
            limit_on = settings["checks"]["max_attempts"]["enabled"]
            removed["members"] += await self.run(
                "DELETE FROM members WHERE guild_id = ? AND status = 'pending' AND MAX(COALESCE(joined_at, 0), COALESCE(last_fail_at, 0)) < ? "
                f"AND kick_at IS NULL {'AND limit_reached_at IS NULL ' if limit_on else ''}AND help_thread_id IS NULL AND first_verified_at IS NULL AND verified_at IS NULL "
                "AND NOT EXISTS (SELECT 1 FROM attempts a WHERE a.guild_id = members.guild_id AND a.user_id = members.user_id) "
                "AND NOT EXISTS (SELECT 1 FROM identifiers i WHERE i.guild_id = members.guild_id AND i.user_id = members.user_id)",
                (guild_id, cutoff))
            # The row that holds a limit needs no name past the date everything else about this person went.
            await self.run("UPDATE members SET username = '', avatar = NULL WHERE guild_id = ? AND status = 'pending' AND limit_reached_at IS NOT NULL "
                           "AND (username != '' OR avatar IS NOT NULL) AND MAX(COALESCE(joined_at, 0), COALESCE(last_fail_at, 0)) < ? "
                           "AND first_verified_at IS NULL AND verified_at IS NULL", (guild_id, cutoff))
        removed["orphans"] = await self._sweep_orphans(now)
        await self.checkpoint()
        return removed

    async def _sweep_orphans(self, now: float) -> int:
        """Delete old rows for a server with no record left, which the per-server rules above never reach.

        The dashboard keeps working after /uninstall, so a key saved then, with the bot removed later, would otherwise stay
        forever. A server that hasn't finished setting up gets the same time to change its mind as one that left. The search runs
        off the main connection, because it reads whole tables.
        """
        count = 0
        cutoff = now - DEPARTED_DAYS * 86400
        for table, age in ORPHAN_AGE.items():
            orphaned = await self.read_all(f"SELECT DISTINCT guild_id FROM {table} WHERE {age} < ? AND guild_id NOT IN (SELECT guild_id FROM guilds)", (cutoff,))
            for row in orphaned:
                count += await self.run(f"DELETE FROM {table} WHERE guild_id = ? AND {age} < ? AND guild_id NOT IN (SELECT guild_id FROM guilds)", (row["guild_id"], cutoff))
        return count
