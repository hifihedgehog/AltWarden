"""Make one encrypted copy of the database while the bot runs. Run with:

    python -m altwarden.backup data/altwarden.db backups/altwarden-copy.db

It reads MASTER_KEY from the environment or .env. The copy opens with the same master key, and the key isn't in it.
"""
from __future__ import annotations

import os
import sys
from pathlib import Path

from dotenv import load_dotenv

from .crypto import Keyring, decode_master_key
from .db import integrity_problems, open_encrypted


class BackupError(RuntimeError):
    """The copy failed its checks, so nothing was put in place."""


def copy_database(source: str | Path, target: str | Path, key: str) -> None:
    """Copy with SQLite's online backup, check the copy, and put it in place with one rename. An older copy stays until the new one passes."""
    target = Path(target)
    temporary = target.with_name(f"{target.name}.new")
    temporary.unlink(missing_ok=True)
    reader = open_encrypted(f"{Path(source).resolve().as_uri()}?mode=ro", key, uri=True)
    try:
        writer = open_encrypted(str(temporary), key)
        try:
            reader.backup(writer)
            problems = integrity_problems(writer)
        finally:
            writer.close()
    finally:
        reader.close()
    if problems:
        temporary.unlink(missing_ok=True)
        raise BackupError(f"The copy failed its integrity check: {problems[0]}")
    os.replace(temporary, target)


def main(arguments: list[str] | None = None) -> int:
    arguments = sys.argv[1:] if arguments is None else arguments
    if len(arguments) != 2:
        print("Usage: python -m altwarden.backup DATABASE COPY", file=sys.stderr)
        return 2
    load_dotenv()
    master = os.environ.get("MASTER_KEY")
    if not master:
        print("MASTER_KEY is missing from the environment and .env.", file=sys.stderr)
        return 2
    try:
        copy_database(arguments[0], arguments[1], Keyring(decode_master_key(master)).database_key())
    except BackupError as error:
        print(error, file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
