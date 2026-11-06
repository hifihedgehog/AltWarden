"""Make a plain, readable copy of an encrypted database, to recover data with any SQLite tool. Run with:

    python -m altwarden.decrypt_database backups/altwarden.db readable.db

It reads MASTER_KEY from the environment or .env. Point it at a nightly copy, or stop the bot first and point it at the live file.
The source stays as it was. The new file exists only if every table matches the source row for row, and only its owner can read it.
"""
from __future__ import annotations

import os
import sys
from pathlib import Path

from dotenv import load_dotenv

from .crypto import Keyring, decode_master_key
from .db import DatabaseKeyError, open_encrypted
from .encrypt_database import ConversionError, _settings, compare, is_plain


def decrypt(source: str | Path, target: str | Path, key: str) -> dict[str, int]:
    """Export an encrypted database into a new plain file with sqlcipher_export, check it, and return each table's row count."""
    source, target = Path(source), Path(target)
    if not source.is_file():
        raise ConversionError(f"{source} doesn't exist.")
    if target.exists():
        raise ConversionError(f"{target} already exists. Move it away first.")
    if is_plain(source):
        raise ConversionError(f"{source} is already plain, so there's nothing to decrypt.")
    connection = open_encrypted(f"{source.resolve().as_uri()}?mode=ro", key, uri=True)
    os.close(os.open(target, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600))  # private before any row is in it
    try:
        user_version, application_id = _settings(connection)
        connection.execute("ATTACH DATABASE ? AS readable KEY ''", (str(target),))
        connection.execute("SELECT sqlcipher_export('readable')").fetchall()
        # sqlcipher_export leaves these two behind.
        connection.execute(f"PRAGMA readable.user_version = {int(user_version)}")
        connection.execute(f"PRAGMA readable.application_id = {int(application_id)}")
        connection.commit()
        connection.execute("DETACH DATABASE readable")
    except Exception:
        connection.close()
        target.unlink(missing_ok=True)
        raise
    connection.close()
    try:
        return compare(target, source, key)
    except Exception:
        target.unlink(missing_ok=True)
        raise


def main(arguments: list[str] | None = None) -> int:
    arguments = sys.argv[1:] if arguments is None else arguments
    if len(arguments) != 2:
        print("Usage: python -m altwarden.decrypt_database ENCRYPTED_DATABASE NEW_PLAIN_FILE", file=sys.stderr)
        return 2
    load_dotenv()
    master = os.environ.get("MASTER_KEY")
    if not master:
        print("MASTER_KEY is missing from the environment and .env.", file=sys.stderr)
        return 2
    try:
        counts = decrypt(arguments[0], arguments[1], Keyring(decode_master_key(master)).database_key())
    except (ConversionError, DatabaseKeyError) as error:
        print(error, file=sys.stderr)
        return 1
    for table, rows in counts.items():
        print(f"{table}: {rows} rows match")
    print(f"{arguments[1]} is plain and readable. Keep it private, and delete it when you're done.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
