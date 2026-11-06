"""Turn a plain database from before version 1.3 into an encrypted one. Stop the bot first, then run:

    python -m altwarden.encrypt_database data/altwarden.db data/altwarden-encrypted.db

It reads MASTER_KEY from the environment or .env. The source stays as it was. The new file exists only if every table
matches the source row for row and the integrity checks pass, so move it over the old one afterward and start the bot.
"""
from __future__ import annotations

import hashlib
import os
import sqlite3
import sys
from pathlib import Path

from dotenv import load_dotenv
from sqlcipher3 import dbapi2 as cipher

from .crypto import Keyring, decode_master_key
from .db import CIPHER_COMPATIBILITY, DatabaseKeyError, integrity_problems, open_encrypted

PLAIN_HEADER = b"SQLite format 3\x00"


class ConversionError(RuntimeError):
    """The database wasn't converted, and this says why. No key is ever in the message."""


def is_plain(path: str | Path) -> bool:
    with open(path, "rb") as file:
        return file.read(len(PLAIN_HEADER)) == PLAIN_HEADER


def plain_sqlite_refuses(path: str | Path) -> bool:
    """Whether Python's own SQLite, which knows nothing about keys, can't read this file."""
    connection = sqlite3.connect(f"{Path(path).resolve().as_uri()}?mode=ro", uri=True)
    try:
        connection.execute("SELECT count(*) FROM sqlite_master").fetchone()
    except sqlite3.DatabaseError:
        return True
    finally:
        connection.close()
    return False


def _table_state(connection, table: str) -> tuple[int, int]:
    """A table's row count, and a hash of its rows that doesn't depend on their order."""
    count = total = 0
    for row in connection.execute(f'SELECT * FROM "{table}"'):
        count += 1
        total += int.from_bytes(hashlib.sha256(repr(tuple(row)).encode("utf-8", "surrogatepass")).digest(), "big")
    return count, total % (1 << 256)


def _settings(connection) -> tuple:
    return connection.execute("PRAGMA user_version").fetchone()[0], connection.execute("PRAGMA application_id").fetchone()[0]


def compare(source: str | Path, target: str | Path, key: str) -> dict[str, int]:
    """Every table's row count, once the encrypted file proves to match the plain one. Raises ConversionError if anything differs."""
    # Nothing writes to the plain file by now, and its log is empty. Marked immutable, it can't leave log files beside itself.
    plain = cipher.connect(f"{Path(source).resolve().as_uri()}?mode=ro&immutable=1", uri=True)
    encrypted = open_encrypted(f"{Path(target).resolve().as_uri()}?mode=ro", key, uri=True)
    try:
        schema = "SELECT type, name, tbl_name, sql FROM sqlite_master"
        expected = set(plain.execute(schema).fetchall())
        if expected != set(encrypted.execute(schema).fetchall()):
            raise ConversionError("The new file's tables, indexes or triggers differ from the source.")
        if _settings(plain) != _settings(encrypted):
            raise ConversionError("The new file's user_version or application_id differs from the source.")
        counts = {}
        for table in sorted(name for kind, name, _, _ in expected if kind == "table"):
            before, after = _table_state(plain, table), _table_state(encrypted, table)
            if before[0] != after[0]:
                raise ConversionError(f"{table} has {before[0]} rows in the source and {after[0]} in the new file.")
            if before[1] != after[1]:
                raise ConversionError(f"{table} has the same number of rows in both files, but they hold different values.")
            counts[table] = before[0]
        problems = integrity_problems(encrypted)
        if problems:
            raise ConversionError(f"The new file failed its integrity check: {problems[0]}")
        return counts
    finally:
        encrypted.close()
        plain.close()


def convert(source: str | Path, target: str | Path, key: str) -> dict[str, int]:
    """Export a plain database into a new encrypted file with sqlcipher_export, check it, and return each table's row count."""
    source, target = Path(source), Path(target)
    if not source.is_file():
        raise ConversionError(f"{source} doesn't exist.")
    if target.exists():
        raise ConversionError(f"{target} already exists. Move it away first.")
    if not is_plain(source):
        raise ConversionError(f"{source} isn't a plain SQLite database. It's probably encrypted already.")
    connection = cipher.connect(str(source))  # no key, so SQLCipher reads a plain file the way SQLite does
    try:
        busy = connection.execute("PRAGMA wal_checkpoint(TRUNCATE)").fetchone()[0]
        if busy:
            raise ConversionError("Something else has this database open. Stop the bot, then run this again.")
        user_version, application_id = _settings(connection)
        connection.execute(f"ATTACH DATABASE ? AS encrypted KEY \"x'{key}'\"", (str(target),))
        connection.execute(f"PRAGMA encrypted.cipher_compatibility = {CIPHER_COMPATIBILITY}")
        connection.execute("SELECT sqlcipher_export('encrypted')").fetchall()
        # sqlcipher_export leaves these two behind.
        connection.execute(f"PRAGMA encrypted.user_version = {int(user_version)}")
        connection.execute(f"PRAGMA encrypted.application_id = {int(application_id)}")
        connection.commit()
        connection.execute("DETACH DATABASE encrypted")
    finally:
        connection.close()
    try:
        counts = compare(source, target, key)
        if not plain_sqlite_refuses(target):
            raise ConversionError("Plain SQLite can read the new file, so it isn't encrypted.")
    except Exception:
        for leftover in (target, Path(f"{target}-wal"), Path(f"{target}-shm")):
            leftover.unlink(missing_ok=True)
        raise
    return counts


def main(arguments: list[str] | None = None) -> int:
    arguments = sys.argv[1:] if arguments is None else arguments
    if len(arguments) != 2:
        print("Usage: python -m altwarden.encrypt_database PLAIN_DATABASE NEW_ENCRYPTED_FILE", file=sys.stderr)
        return 2
    load_dotenv()
    master = os.environ.get("MASTER_KEY")
    if not master:
        print("MASTER_KEY is missing from the environment and .env.", file=sys.stderr)
        return 2
    try:
        counts = convert(arguments[0], arguments[1], Keyring(decode_master_key(master)).database_key())
    except (ConversionError, DatabaseKeyError) as error:
        print(error, file=sys.stderr)
        return 1
    for table, rows in counts.items():
        print(f"{table}: {rows} rows match")
    print("cipher_integrity_check and integrity_check passed. Plain SQLite can't read the new file.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
