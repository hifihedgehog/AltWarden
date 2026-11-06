"""The database at rest: what its file and log show without the key, what the key is, and how copies and conversions keep it that way."""
import asyncio
import hashlib
import logging
import os
import shutil
import sqlite3
import sys
import tempfile
import threading
import unittest
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from altwarden import __main__ as entry, backup, crypto, db as db_module, decrypt_database, encrypt_database
from fakes import DB_KEY

OTHER_KEY = "cd" * 32
MARK = "someoneinparticular"


def plain_sqlite_reads(path):
    """What Python's own SQLite says about a file and its log: its table count, or the refusal.

    It reads copies. Two SQLite libraries in one process can't see each other's file locks on Linux, and a stock
    connection that saw an empty main file would take the log beside it for a leftover and delete it.
    """
    with tempfile.TemporaryDirectory(ignore_cleanup_errors=True) as folder:
        copy = os.path.join(folder, "copy.db")
        shutil.copy(path, copy)
        if os.path.exists(f"{path}-wal"):
            shutil.copy(f"{path}-wal", f"{copy}-wal")
        connection = sqlite3.connect(copy)
        try:
            return connection.execute("SELECT count(*) FROM sqlite_master").fetchone()[0]
        except sqlite3.DatabaseError as error:
            return str(error)
        finally:
            connection.close()


def holds(path, text=MARK):
    return text.encode() in Path(path).read_bytes()


def file_hash(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


class Folder(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        self.folder = tempfile.TemporaryDirectory(ignore_cleanup_errors=True)
        self.addCleanup(self.folder.cleanup)
        self.path = os.path.join(self.folder.name, "t.db")

    async def opened(self, path=None, key=DB_KEY):
        database = db_module.Database(path or self.path, key)
        await database.open()
        self.addAsyncCleanup(database.close)
        return database


class TheFileAndItsLog(Folder):
    async def test_a_plain_file_shows_the_name_as_a_control(self):
        connection = sqlite3.connect(self.path)
        connection.execute("CREATE TABLE members (username TEXT)")
        connection.execute("INSERT INTO members VALUES (?)", (MARK,))
        connection.commit()
        connection.close()
        self.assertTrue(holds(self.path))
        self.assertTrue(Path(self.path).read_bytes().startswith(b"SQLite format 3"))
        self.assertEqual(plain_sqlite_reads(self.path), 1)

    async def test_the_file_and_log_show_nothing_while_rows_sit_in_the_log(self):
        database = await self.opened()
        await database.touch_member("1", "2", username=MARK)
        wal = self.path + "-wal"
        self.assertGreater(os.path.getsize(wal), 0, "the row has to be in the log for this to prove anything")
        self.assertFalse(holds(wal))
        self.assertFalse(holds(wal, "CREATE TABLE"))
        self.assertFalse(holds(self.path))
        self.assertFalse(Path(self.path).read_bytes().startswith(b"SQLite format 3"))

    async def test_the_file_shows_nothing_after_a_checkpoint(self):
        database = await self.opened()
        await database.touch_member("1", "2", username=MARK)
        self.assertTrue(await database.checkpoint())
        self.assertEqual(os.path.getsize(self.path + "-wal"), 0)
        for text in (MARK, "CREATE TABLE", "identifiers"):
            self.assertFalse(holds(self.path, text), text)

    async def test_plain_sqlite_refuses_the_file_and_a_copy_with_its_log(self):
        database = await self.opened()
        await database.touch_member("1", "2", username=MARK)
        await database.checkpoint()
        await database.touch_member("1", "3", username=MARK)
        self.assertGreater(os.path.getsize(self.path + "-wal"), 0)
        self.assertEqual(plain_sqlite_reads(self.path), "file is not a database")

    async def test_the_key_isnt_in_the_file_or_its_log(self):
        database = await self.opened()
        await database.touch_member("1", "2", username=MARK)
        await database.checkpoint()
        await database.touch_member("1", "3", username=MARK)
        for path in (self.path, self.path + "-wal"):
            self.assertFalse(holds(path, DB_KEY), path)
            self.assertNotIn(bytes.fromhex(DB_KEY), Path(path).read_bytes(), path)

    async def test_the_values_come_back_with_the_key(self):
        database = await self.opened()
        await database.touch_member("1", "2", username=MARK)
        await database.close()
        again = await self.opened()
        self.assertEqual((await again.member("1", "2"))["username"], MARK)

    async def test_the_file_keeps_its_write_ahead_log(self):
        database = await self.opened()
        self.assertEqual(await database.scalar("PRAGMA journal_mode"), "wal")
        self.assertEqual(await database.scalar("PRAGMA secure_delete"), 1)


class OpeningIt(Folder):
    async def wrote_with(self, key):
        database = await self.opened(key=key)
        await database.touch_member("1", "2", username=MARK)
        await database.close()

    def threads_settle(self, before):
        for _ in range(100):
            if threading.active_count() <= before:
                return True
            threading.Event().wait(0.01)
        return False

    async def test_another_key_is_refused_and_says_what_to_do(self):
        await self.wrote_with(DB_KEY)
        before = threading.active_count()
        database = db_module.Database(self.path, OTHER_KEY)
        with self.assertRaises(db_module.DatabaseKeyError) as caught:
            await database.open()
        self.assertIn("encrypt_database", str(caught.exception))
        self.assertIn("put that key back", str(caught.exception))
        self.assertNotIn(OTHER_KEY, str(caught.exception))
        self.assertTrue(self.threads_settle(before), "a worker thread left behind keeps the process from ever exiting")

    async def test_a_plain_database_is_refused_and_left_alone(self):
        connection = sqlite3.connect(self.path)
        connection.execute("CREATE TABLE members (username TEXT)")
        connection.commit()
        connection.close()
        before = file_hash(self.path)
        database = db_module.Database(self.path, DB_KEY)
        with self.assertRaises(db_module.DatabaseKeyError):
            await database.open()
        self.assertEqual(file_hash(self.path), before)

    async def test_a_key_of_the_wrong_shape_never_reaches_the_pragma(self):
        for key in ("", "ab", DB_KEY.upper(), DB_KEY[:-1] + '"', "x" * 64):
            with self.assertRaises(ValueError, msg=key):
                db_module.Database(self.path, key)

    async def test_a_new_database_is_encrypted_from_its_first_write(self):
        await self.opened()
        self.assertEqual(plain_sqlite_reads(self.path), "file is not a database")

    async def test_the_process_stops_and_stays_stopped_on_a_key_it_cant_use(self):
        async def refuse(_):
            raise db_module.DatabaseKeyError("This MASTER_KEY can't open the database.")
        environment = {"DISCORD_TOKEN": "x", "DISCORD_CLIENT_SECRET": "x", "MASTER_KEY": "x"}
        with patch.object(entry, "run", refuse), patch.object(entry, "load_dotenv"), patch.dict(os.environ, environment), \
                patch.object(sys, "argv", ["altwarden", "--public-url", "https://example.test"]), patch.object(logging, "basicConfig"), \
                self.assertLogs("altwarden", "CRITICAL") as logs:
            with self.assertRaises(SystemExit) as stopped:
                await asyncio.to_thread(entry.main)
        self.assertEqual(stopped.exception.code, entry.EXIT_NO_RESTART)
        self.assertIn("can't open the database", logs.output[0])


class TheReader(Folder):
    async def test_it_reads_rows_still_in_the_log(self):
        database = await self.opened()
        await database.touch_member("1", "2", username=MARK)
        self.assertEqual((await database.read_all("SELECT username FROM members"))[0]["username"], MARK)

    async def test_its_rows_read_by_name(self):
        database = await self.opened()
        await database.touch_member("1", "2", username=MARK)
        reader = database.reader()
        try:
            self.assertEqual(reader.execute("SELECT username FROM members").fetchone()["username"], MARK)
        finally:
            reader.close()

    async def test_it_can_only_read(self):
        database = await self.opened()
        reader = database.reader()
        try:
            with self.assertRaises(db_module.cipher.OperationalError):
                reader.execute("DELETE FROM members")
        finally:
            reader.close()

    async def test_it_works_during_an_open_write(self):
        database = await self.opened()
        await database.touch_member("1", "2", username=MARK)
        await database.conn.execute("DELETE FROM members")
        self.assertEqual(len(await database.read_all("SELECT username FROM members")), 1)
        await database.conn.rollback()

    async def test_a_checkpoint_held_up_by_a_reader_says_so_and_recovers(self):
        database = await self.opened()
        await database.touch_member("1", "2", username=MARK)
        reader = database.reader()
        reader.execute("BEGIN")
        reader.execute("SELECT * FROM members").fetchall()
        await database.touch_member("1", "3", username=MARK)
        self.assertFalse(await database.checkpoint())
        reader.close()
        self.assertTrue(await database.checkpoint())


class Checkpoints(Folder):
    async def test_a_refusal_from_sqlcipher_itself_counts_as_held_up(self):
        database = await self.opened()
        await database.touch_member("1", "2", username=MARK)
        before = await database.scalar("PRAGMA busy_timeout")
        with patch.object(database.conn, "execute_fetchall", side_effect=db_module.cipher.OperationalError("database table is locked")):
            self.assertFalse(await database.checkpoint())
        self.assertEqual(await database.scalar("PRAGMA busy_timeout"), before)
        self.assertTrue(await database.checkpoint())


class DamagedFiles(Folder):
    async def damaged(self):
        database = await self.opened()
        await database.run_many("INSERT INTO meta (key, value) VALUES (?, ?)", [(f"key{number}", number) for number in range(2000)])
        await database.checkpoint()
        await database.close()
        data = bytearray(Path(self.path).read_bytes())
        self.assertGreater(len(data), 3 * 4096)
        data[2 * 4096 + 100] ^= 0xFF  # one bit pattern in the middle of the third page
        Path(self.path).write_bytes(bytes(data))

    async def test_one_changed_byte_is_found(self):
        await self.damaged()
        connection = db_module.open_encrypted(self.path, DB_KEY)
        try:
            problems = db_module.integrity_problems(connection)
        finally:
            connection.close()
        self.assertTrue(problems)
        self.assertIn("HMAC", " ".join(problems).upper())

    async def test_a_damaged_file_is_never_copied_as_good(self):
        await self.damaged()
        target = os.path.join(self.folder.name, "copy.db")
        with self.assertRaises(Exception):
            await asyncio.to_thread(backup.copy_database, self.path, target, DB_KEY)
        self.assertFalse(os.path.exists(target))


class TheBotsOwnKey(unittest.IsolatedAsyncioTestCase):
    async def test_the_bot_opens_its_database_with_the_key_from_its_master_key(self):
        master = crypto.new_master_key()
        seen = {}

        class Stops(db_module.Database):
            def __init__(self, path, key):
                seen["key"] = key
                super().__init__(path, key)

            async def open(self):
                raise db_module.DatabaseKeyError("stop here")
        with tempfile.TemporaryDirectory(ignore_cleanup_errors=True) as folder, patch.object(entry, "Database", Stops), patch.dict(os.environ, {"MASTER_KEY": master}):
            arguments = entry.argparse.Namespace(data=folder, public_url="https://example.test", host="127.0.0.1", port=1)
            with self.assertRaises(db_module.DatabaseKeyError):
                await entry.run(arguments)
        self.assertEqual(seen["key"], crypto.Keyring(crypto.decode_master_key(master)).database_key())


class TheKey(unittest.TestCase):
    MASTER = b"m" * 32

    def test_it_is_the_raw_form_sqlcipher_takes(self):
        key = crypto.Keyring(self.MASTER).database_key()
        self.assertRegex(key, r"^[0-9a-f]{64}$")
        db_module.Database("unused", key)

    def test_it_comes_from_the_master_key_and_this_purpose_alone(self):
        keys = crypto.Keyring(self.MASTER)
        self.assertEqual(keys.database_key(), crypto.hkdf_sha256(self.MASTER, info=b"altwarden/database/").hex())
        self.assertEqual(keys.database_key(), crypto.Keyring(self.MASTER).database_key())
        self.assertNotEqual(keys.database_key(), crypto.Keyring(b"n" * 32).database_key())
        self.assertNotEqual(keys.database_key(), keys.derive("identifier", "1/ip").hex())

    def test_nothing_prints_it(self):
        path = "unused"
        database = db_module.Database(path, DB_KEY)
        self.assertNotIn(DB_KEY, repr(database))
        self.assertNotIn(DB_KEY, str(vars(crypto.Keyring(self.MASTER)).keys()))


class NightlyCopies(Folder):
    def setUp(self):
        super().setUp()
        self.target = os.path.join(self.folder.name, "copy.db")

    async def test_a_copy_is_encrypted_holds_every_row_and_opens_with_the_key(self):
        database = await self.opened()
        await database.touch_member("1", "2", username=MARK)
        await database.touch_member("1", "3", username=MARK)  # still in the log when the copy is made
        await asyncio.to_thread(backup.copy_database, self.path, self.target, DB_KEY)
        self.assertFalse(holds(self.target))
        self.assertEqual(plain_sqlite_reads(self.target), "file is not a database")
        copy = db_module.open_encrypted(self.target, DB_KEY)
        try:
            self.assertEqual(copy.execute("SELECT count(*) FROM members").fetchone()[0], 2)
            self.assertEqual(db_module.integrity_problems(copy), [])
        finally:
            copy.close()

    async def test_a_copy_wont_open_with_another_key(self):
        await self.opened()
        await asyncio.to_thread(backup.copy_database, self.path, self.target, DB_KEY)
        with self.assertRaises(db_module.DatabaseKeyError):
            db_module.open_encrypted(self.target, OTHER_KEY)

    async def test_a_copy_that_fails_its_check_leaves_the_older_one(self):
        await self.opened()
        Path(self.target).write_text("older copy")
        with patch.object(backup, "integrity_problems", return_value=["a bad page"]):
            with self.assertRaises(backup.BackupError):
                await asyncio.to_thread(backup.copy_database, self.path, self.target, DB_KEY)
        self.assertEqual(Path(self.target).read_text(), "older copy")
        self.assertEqual(sorted(name for name in os.listdir(self.folder.name) if "copy" in name), ["copy.db"])

    async def test_a_scrap_left_by_a_crashed_copy_doesnt_stop_the_next_one(self):
        await self.opened()
        Path(self.target + ".new").write_text("half a file from a run that died")
        await asyncio.to_thread(backup.copy_database, self.path, self.target, DB_KEY)
        db_module.open_encrypted(self.target, DB_KEY).close()
        self.assertFalse(os.path.exists(self.target + ".new"))

    async def test_the_same_nights_copy_is_replaced(self):
        database = await self.opened()
        await asyncio.to_thread(backup.copy_database, self.path, self.target, DB_KEY)
        await database.touch_member("1", "2", username=MARK)
        await asyncio.to_thread(backup.copy_database, self.path, self.target, DB_KEY)
        copy = db_module.open_encrypted(self.target, DB_KEY)
        try:
            self.assertEqual(copy.execute("SELECT count(*) FROM members").fetchone()[0], 1)
        finally:
            copy.close()

    async def test_the_command_derives_the_same_key_as_the_bot(self):
        master = crypto.new_master_key()
        database = await self.opened(key=crypto.Keyring(crypto.decode_master_key(master)).database_key())
        await database.touch_member("1", "2", username=MARK)
        with patch.dict(os.environ, {"MASTER_KEY": master}), patch.object(backup, "load_dotenv"):
            self.assertEqual(await asyncio.to_thread(backup.main, [self.path, self.target]), 0)
        self.assertEqual(plain_sqlite_reads(self.target), "file is not a database")

    def test_the_command_says_what_it_needs(self):
        with patch.object(backup, "load_dotenv"), patch.dict(os.environ, {}, clear=True):
            self.assertEqual(backup.main(["a", "b"]), 2)
        self.assertEqual(backup.main([]), 2)


class Converting(Folder):
    def setUp(self):
        super().setUp()
        self.target = os.path.join(self.folder.name, "encrypted.db")
        connection = sqlite3.connect(self.path)
        connection.execute("PRAGMA journal_mode=WAL")
        connection.execute("PRAGMA user_version=9")
        connection.execute("PRAGMA application_id=77")
        connection.executescript("""
            CREATE TABLE members (id INTEGER PRIMARY KEY, username TEXT NOT NULL UNIQUE, joined REAL, photo BLOB);
            CREATE INDEX members_joined ON members (joined);
            CREATE TRIGGER members_gone AFTER DELETE ON members BEGIN SELECT 1; END;
            CREATE TABLE notes (id INTEGER PRIMARY KEY AUTOINCREMENT, body TEXT);
            CREATE TABLE empty_one (a TEXT);
        """)
        connection.executemany("INSERT INTO members (username, joined, photo) VALUES (?, ?, ?)",
                               [(f"{MARK}{number}", number / 3, bytes([number % 256]) * 8) for number in range(500)])
        connection.execute("INSERT INTO notes (body) VALUES ('kept'), ('gone')")
        connection.execute("DELETE FROM notes WHERE body = 'gone'")
        connection.commit()
        connection.close()

    def stored(self, connection):
        return (connection.execute("SELECT * FROM members ORDER BY id").fetchall(), connection.execute("SELECT * FROM sqlite_sequence").fetchall(),
                connection.execute("PRAGMA user_version").fetchone()[0], connection.execute("PRAGMA application_id").fetchone()[0])

    def test_it_carries_every_row_and_leaves_the_source(self):
        plain = sqlite3.connect(self.path)
        expected = self.stored(plain)
        plain.close()
        before = file_hash(self.path)
        counts = encrypt_database.convert(self.path, self.target, DB_KEY)
        self.assertEqual(counts, {"empty_one": 0, "members": 500, "notes": 1, "sqlite_sequence": 1})
        self.assertEqual(file_hash(self.path), before)
        self.assertFalse(holds(self.target))
        self.assertEqual(plain_sqlite_reads(self.target), "file is not a database")
        encrypted = db_module.open_encrypted(self.target, DB_KEY)
        try:
            self.assertEqual(self.stored(encrypted), expected)
            self.assertEqual({row[0] for row in encrypted.execute("SELECT name FROM sqlite_master WHERE type IN ('index', 'trigger') AND sql IS NOT NULL")},
                             {"members_joined", "members_gone"})
            self.assertEqual(db_module.integrity_problems(encrypted), [])
        finally:
            encrypted.close()

    def test_it_leaves_no_files_beside_the_source_or_the_new_one(self):
        encrypt_database.convert(self.path, self.target, DB_KEY)
        self.assertEqual(sorted(os.listdir(self.folder.name)), ["encrypted.db", "t.db"])

    def test_rows_waiting_in_the_log_are_carried_too(self):
        writer = sqlite3.connect(self.path)
        writer.execute("PRAGMA wal_autocheckpoint=0")
        writer.execute("INSERT INTO notes (body) VALUES ('only in the log')")
        writer.commit()
        shutil.copy(self.path, self.path + ".copy")
        shutil.copy(self.path + "-wal", self.path + ".copy-wal")
        writer.close()
        counts = encrypt_database.convert(self.path + ".copy", self.target, DB_KEY)
        self.assertEqual(counts["notes"], 2)

    async def test_the_bot_opens_the_result(self):
        source = os.path.join(self.folder.name, "bot.db")
        connection = sqlite3.connect(source)
        connection.execute("PRAGMA journal_mode=WAL")
        connection.executescript(db_module.SCHEMA)
        connection.execute("INSERT INTO members (guild_id, user_id, username) VALUES ('1', '2', ?)", (MARK,))
        connection.commit()
        connection.close()
        encrypt_database.convert(source, self.target, DB_KEY)
        database = await self.opened(self.target)
        self.assertEqual((await database.member("1", "2"))["username"], MARK)
        self.assertEqual(await database.scalar("PRAGMA journal_mode"), "wal")
        await database.touch_member("1", "3", username=MARK)
        self.assertFalse(holds(self.target + "-wal"))

    def test_a_database_someone_has_open_is_refused(self):
        holder = db_module.cipher.connect(self.path)
        holder.execute("BEGIN")
        holder.execute("SELECT * FROM members").fetchall()
        writer = db_module.cipher.connect(self.path)
        writer.execute("INSERT INTO notes (body) VALUES ('after the reader')")
        writer.commit()
        writer.close()
        try:
            with self.assertRaisesRegex(encrypt_database.ConversionError, "Stop the bot"):
                encrypt_database.convert(self.path, self.target, DB_KEY)
        finally:
            holder.close()
        self.assertFalse(os.path.exists(self.target))

    def test_an_encrypted_source_is_refused(self):
        encrypt_database.convert(self.path, self.target, DB_KEY)
        with self.assertRaisesRegex(encrypt_database.ConversionError, "encrypted already"):
            encrypt_database.convert(self.target, self.target + ".again", DB_KEY)
        self.assertFalse(os.path.exists(self.target + ".again"))

    def test_it_wont_write_over_a_file(self):
        Path(self.target).write_text("something")
        with self.assertRaisesRegex(encrypt_database.ConversionError, "already exists"):
            encrypt_database.convert(self.path, self.target, DB_KEY)
        self.assertEqual(Path(self.target).read_text(), "something")

    def test_a_missing_source_is_said_plainly(self):
        with self.assertRaisesRegex(encrypt_database.ConversionError, "doesn't exist"):
            encrypt_database.convert(self.path + ".nope", self.target, DB_KEY)

    def test_a_copy_that_differs_leaves_no_new_file(self):
        real = encrypt_database._table_state
        calls = {"count": 0}

        def off_by_one(connection, table):
            calls["count"] += 1
            count, total = real(connection, table)
            return (count + 1, total) if calls["count"] == 2 else (count, total)
        with patch.object(encrypt_database, "_table_state", off_by_one):
            with self.assertRaisesRegex(encrypt_database.ConversionError, "rows in the source"):
                encrypt_database.convert(self.path, self.target, DB_KEY)
        self.assertFalse(os.path.exists(self.target))

    def test_same_row_count_with_different_values_is_caught(self):
        encrypt_database.convert(self.path, self.target, DB_KEY)
        encrypted = db_module.open_encrypted(self.target, DB_KEY)
        encrypted.execute("UPDATE notes SET body = 'changed'")
        encrypted.commit()
        encrypted.close()
        with self.assertRaisesRegex(encrypt_database.ConversionError, "different values"):
            encrypt_database.compare(self.path, self.target, DB_KEY)

    def test_a_changed_schema_is_caught(self):
        encrypt_database.convert(self.path, self.target, DB_KEY)
        encrypted = db_module.open_encrypted(self.target, DB_KEY)
        encrypted.execute("DROP INDEX members_joined")
        encrypted.commit()
        encrypted.close()
        with self.assertRaisesRegex(encrypt_database.ConversionError, "tables, indexes or triggers"):
            encrypt_database.compare(self.path, self.target, DB_KEY)

    def test_a_changed_user_version_is_caught(self):
        encrypt_database.convert(self.path, self.target, DB_KEY)
        encrypted = db_module.open_encrypted(self.target, DB_KEY)
        encrypted.execute("PRAGMA user_version=1")
        encrypted.commit()
        encrypted.close()
        with self.assertRaisesRegex(encrypt_database.ConversionError, "user_version"):
            encrypt_database.compare(self.path, self.target, DB_KEY)

    def test_a_failed_integrity_check_is_caught(self):
        encrypt_database.convert(self.path, self.target, DB_KEY)
        with patch.object(encrypt_database, "integrity_problems", return_value=["a bad page"]):
            with self.assertRaisesRegex(encrypt_database.ConversionError, "a bad page"):
                encrypt_database.compare(self.path, self.target, DB_KEY)

    def test_a_file_plain_sqlite_can_read_is_never_kept(self):
        with patch.object(encrypt_database, "plain_sqlite_refuses", return_value=False):
            with self.assertRaisesRegex(encrypt_database.ConversionError, "isn't encrypted"):
                encrypt_database.convert(self.path, self.target, DB_KEY)
        self.assertFalse(os.path.exists(self.target))

    def test_the_command_reports_each_table_and_keeps_the_key_out(self):
        master = crypto.new_master_key()
        key = crypto.Keyring(crypto.decode_master_key(master)).database_key()
        with patch.dict(os.environ, {"MASTER_KEY": master}), patch.object(encrypt_database, "load_dotenv"), patch("builtins.print") as printed:
            self.assertEqual(encrypt_database.main([self.path, self.target]), 0)
        said = "\n".join(str(call.args[0]) for call in printed.call_args_list)
        self.assertIn("members: 500 rows match", said)
        self.assertIn("Plain SQLite can't read the new file", said)
        self.assertNotIn(key, said)
        self.assertNotIn(master, said)
        with self.assertRaises(db_module.DatabaseKeyError):
            db_module.open_encrypted(self.target, DB_KEY)
        db_module.open_encrypted(self.target, key).close()

    def test_the_command_fails_loudly_and_says_what_it_needs(self):
        with patch.dict(os.environ, {"MASTER_KEY": crypto.new_master_key()}), patch.object(encrypt_database, "load_dotenv"):
            self.assertEqual(encrypt_database.main([self.path + ".nope", self.target]), 1)
        self.assertEqual(encrypt_database.main([]), 2)
        with patch.object(encrypt_database, "load_dotenv"), patch.dict(os.environ, {}, clear=True):
            self.assertEqual(encrypt_database.main(["a", "b"]), 2)


class GettingTheDataBack(Folder):
    def setUp(self):
        super().setUp()
        self.readable = os.path.join(self.folder.name, "readable.db")
        self.copy = os.path.join(self.folder.name, "nightly.db")

    async def with_rows(self):
        database = await self.opened()
        await database.touch_member("1", "2", username=MARK)
        await database.touch_member("1", "3", username=MARK + "2")
        await database.set_meta("mark", 7.0)
        return database

    async def test_a_nightly_copy_goes_back_in_place_and_the_bot_opens_it(self):
        database = await self.with_rows()
        await asyncio.to_thread(backup.copy_database, self.path, self.copy, DB_KEY)
        await database.touch_member("1", "4", username="after the copy")
        await database.close()
        for leftover in (self.path + "-wal", self.path + "-shm"):
            Path(leftover).unlink(missing_ok=True)
        shutil.copy(self.copy, self.path)
        again = await self.opened()
        self.assertEqual(await again.scalar("SELECT count(*) FROM members"), 2)
        self.assertEqual((await again.member("1", "2"))["username"], MARK)
        self.assertIsNone(await again.member("1", "4"))

    async def test_a_nightly_copy_turns_into_a_file_any_sqlite_tool_reads(self):
        database = await self.with_rows()
        await asyncio.to_thread(backup.copy_database, self.path, self.copy, DB_KEY)
        before = file_hash(self.copy)
        counts = await asyncio.to_thread(decrypt_database.decrypt, self.copy, self.readable, DB_KEY)
        self.assertEqual(counts["members"], 2)
        self.assertEqual(file_hash(self.copy), before)
        self.assertTrue(holds(self.readable))
        plain = sqlite3.connect(self.readable)
        try:
            self.assertEqual(sorted(row[0] for row in plain.execute("SELECT username FROM members")), [MARK, MARK + "2"])
            self.assertEqual(plain.execute("SELECT value FROM meta WHERE key = 'mark'").fetchone()[0], 7.0)
        finally:
            plain.close()
        await database.close()

    async def test_the_live_file_decrypts_with_the_bot_stopped(self):
        database = await self.with_rows()
        await database.close()
        counts = await asyncio.to_thread(decrypt_database.decrypt, self.path, self.readable, DB_KEY)
        self.assertEqual(counts["members"], 2)

    async def test_rows_still_in_the_log_come_back_too(self):
        database = await self.with_rows()
        self.assertGreater(os.path.getsize(self.path + "-wal"), 0)
        counts = await asyncio.to_thread(decrypt_database.decrypt, self.path, self.readable, DB_KEY)
        self.assertEqual(counts["members"], 2)
        await database.close()

    async def test_only_its_owner_can_read_the_plain_copy(self):
        await self.with_rows()
        await asyncio.to_thread(decrypt_database.decrypt, self.path, self.readable, DB_KEY)
        if os.name == "posix":
            self.assertEqual(os.stat(self.readable).st_mode & 0o777, 0o600)

    async def test_a_round_trip_changes_nothing(self):
        database = await self.with_rows()
        await database.close()
        back = os.path.join(self.folder.name, "back.db")
        first = await asyncio.to_thread(decrypt_database.decrypt, self.path, self.readable, DB_KEY)
        second = await asyncio.to_thread(encrypt_database.convert, self.readable, back, OTHER_KEY)
        self.assertEqual(first, second)
        self.assertEqual(plain_sqlite_reads(back), "file is not a database")

    async def test_another_key_gets_nothing_and_leaves_nothing(self):
        await self.with_rows()
        with self.assertRaises(db_module.DatabaseKeyError):
            await asyncio.to_thread(decrypt_database.decrypt, self.path, self.readable, OTHER_KEY)
        self.assertFalse(os.path.exists(self.readable))

    async def test_a_copy_that_differs_leaves_no_plain_file(self):
        await self.with_rows()
        with patch.object(decrypt_database, "compare", side_effect=encrypt_database.ConversionError("differs")):
            with self.assertRaises(encrypt_database.ConversionError):
                await asyncio.to_thread(decrypt_database.decrypt, self.path, self.readable, DB_KEY)
        self.assertFalse(os.path.exists(self.readable))

    async def test_a_plain_source_and_a_taken_target_are_refused(self):
        await self.with_rows()
        plain = os.path.join(self.folder.name, "plain.db")
        connection = sqlite3.connect(plain)
        connection.execute("CREATE TABLE t (a)")
        connection.commit()
        connection.close()
        with self.assertRaisesRegex(encrypt_database.ConversionError, "already plain"):
            decrypt_database.decrypt(plain, self.readable, DB_KEY)
        Path(self.readable).write_text("something")
        with self.assertRaisesRegex(encrypt_database.ConversionError, "already exists"):
            decrypt_database.decrypt(self.path, self.readable, DB_KEY)
        self.assertEqual(Path(self.readable).read_text(), "something")
        with self.assertRaisesRegex(encrypt_database.ConversionError, "doesn't exist"):
            decrypt_database.decrypt(self.path + ".nope", self.readable + "2", DB_KEY)

    async def test_the_command_reports_and_keeps_the_key_out(self):
        master = crypto.new_master_key()
        key = crypto.Keyring(crypto.decode_master_key(master)).database_key()
        database = await self.opened(key=key)
        await database.touch_member("1", "2", username=MARK)
        with patch.dict(os.environ, {"MASTER_KEY": master}), patch.object(decrypt_database, "load_dotenv"), patch("builtins.print") as printed:
            self.assertEqual(await asyncio.to_thread(decrypt_database.main, [self.path, self.readable]), 0)
        said = "\n".join(str(call.args[0]) for call in printed.call_args_list)
        self.assertIn("members: 1 rows match", said)
        self.assertIn("delete it when you're done", said)
        self.assertNotIn(key, said)
        self.assertNotIn(master, said)

    async def test_the_command_says_when_the_key_is_wrong(self):
        await self.with_rows()
        with patch.dict(os.environ, {"MASTER_KEY": crypto.new_master_key()}), patch.object(decrypt_database, "load_dotenv"):
            self.assertEqual(await asyncio.to_thread(decrypt_database.main, [self.path, self.readable]), 1)
        self.assertEqual(decrypt_database.main([]), 2)
        with patch.object(decrypt_database, "load_dotenv"), patch.dict(os.environ, {}, clear=True):
            self.assertEqual(decrypt_database.main(["a", "b"]), 2)


if __name__ == "__main__":
    unittest.main()
