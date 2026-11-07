import sqlite3
from concurrent.futures import ThreadPoolExecutor
from threading import Barrier
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest.mock import patch

from origin_trader.storage.sqlite_store import (
    DatabaseMissingError,
    SCHEMA_VERSION,
    SQLiteStore,
    StorageError,
)


class StorageTests(unittest.TestCase):

    def test_database_is_created_with_correct_schema(self):
        with TemporaryDirectory() as directory:
            database = Path(directory) / "origin.sqlite3"

            with SQLiteStore.initialize(database):
                self.assertTrue(database.exists())

            connection = sqlite3.connect(database)

            try:
                version = connection.execute(
                    "PRAGMA user_version"
                ).fetchone()[0]

                self.assertEqual(version, SCHEMA_VERSION)

            finally:
                connection.close()

    def test_opening_missing_database_fails_without_creating_a_file(self):
        with TemporaryDirectory() as directory:
            database = Path(directory) / "missing.sqlite3"
            self.assertFalse(database.exists())

            with self.assertRaisesRegex(DatabaseMissingError, "does not exist"):
                SQLiteStore(database)

            self.assertFalse(database.exists())

    def test_deleted_established_database_is_not_recreated(self):
        with TemporaryDirectory() as directory:
            database = Path(directory) / "established.sqlite3"
            with SQLiteStore.initialize(database) as store:
                store.record_event("historical_event", {"value": 7})

            database.unlink()
            with self.assertRaises(DatabaseMissingError):
                SQLiteStore(database)
            self.assertFalse(database.exists())

    def test_initialization_refuses_existing_database_without_overwriting(self):
        with TemporaryDirectory() as directory:
            database = Path(directory) / "existing.sqlite3"
            with SQLiteStore.initialize(database) as store:
                store.record_event("preserve_me", {"value": 9})

            with self.assertRaisesRegex(StorageError, "already exists"):
                SQLiteStore.initialize(database)

            self.assertTrue(database.is_file())
            with SQLiteStore(database) as store:
                events = store.read_events()
            self.assertEqual(len(events), 1)
            self.assertEqual(events[0].event_type, "preserve_me")
            self.assertEqual(events[0].payload, {"value": 9})

    def test_concurrent_initialization_has_one_winner_and_preserves_data(self):
        with TemporaryDirectory() as directory:
            database = Path(directory) / "concurrent.sqlite3"
            barrier = Barrier(2)

            def initialize_once():
                barrier.wait()
                try:
                    with SQLiteStore.initialize(database) as store:
                        store.record_event("winning_initialization")
                    return "initialized"
                except StorageError:
                    return "refused"

            with ThreadPoolExecutor(max_workers=2) as executor:
                outcomes = list(executor.map(lambda _: initialize_once(), range(2)))

            self.assertCountEqual(outcomes, ["initialized", "refused"])
            self.assertTrue(database.is_file())
            with SQLiteStore(database) as store:
                events = store.read_events()
            self.assertEqual(len(events), 1)
            self.assertEqual(events[0].event_type, "winning_initialization")

    def test_initialization_failure_after_exclusive_create_preserves_file(self):
        with TemporaryDirectory() as directory:
            database = Path(directory) / "interrupted-before-schema.sqlite3"

            with patch.object(
                SQLiteStore,
                "_connect_existing",
                side_effect=sqlite3.OperationalError("injected open failure"),
            ):
                with self.assertRaisesRegex(StorageError, "Could not initialize"):
                    SQLiteStore.initialize(database)

            self.assertTrue(database.is_file())
            connection = sqlite3.connect(database)
            try:
                self.assertEqual(
                    connection.execute("PRAGMA user_version").fetchone()[0], 0
                )
                objects = connection.execute(
                    """
                    SELECT name
                    FROM sqlite_master
                    WHERE name NOT LIKE 'sqlite_%'
                    """
                ).fetchall()
                self.assertEqual(objects, [])
            finally:
                connection.close()

            with self.assertRaises(StorageError):
                SQLiteStore(database)
            self.assertTrue(database.is_file())
            with self.assertRaisesRegex(StorageError, "already exists"):
                SQLiteStore.initialize(database)

    def test_schema_creation_failure_rolls_back_and_preserves_file(self):
        with TemporaryDirectory() as directory:
            database = Path(directory) / "interrupted-during-schema.sqlite3"

            def fail_after_schema_ddl(store, expected_version):
                self.assertEqual(expected_version, SCHEMA_VERSION)
                names = {
                    row[0]
                    for row in store._connection.execute(
                        "SELECT name FROM sqlite_master WHERE type = 'table'"
                    )
                }
                self.assertIn("system_events", names)
                self.assertEqual(
                    store._connection.execute(
                        "PRAGMA user_version"
                    ).fetchone()[0],
                    SCHEMA_VERSION,
                )
                raise StorageError("injected failure after schema DDL")

            with patch.object(
                SQLiteStore,
                "_verify_schema",
                fail_after_schema_ddl,
            ):
                with self.assertRaisesRegex(StorageError, "after schema DDL"):
                    SQLiteStore.initialize(database)

            self.assertTrue(database.is_file())
            connection = sqlite3.connect(database)
            try:
                self.assertEqual(
                    connection.execute("PRAGMA user_version").fetchone()[0], 0
                )
                objects = connection.execute(
                    """
                    SELECT name
                    FROM sqlite_master
                    WHERE name NOT LIKE 'sqlite_%'
                    """
                ).fetchall()
                self.assertEqual(objects, [])
                self.assertEqual(
                    connection.execute("PRAGMA integrity_check").fetchone()[0],
                    "ok",
                )
            finally:
                connection.close()

            with self.assertRaises(StorageError):
                SQLiteStore(database)
            self.assertTrue(database.is_file())
            with self.assertRaisesRegex(StorageError, "already exists"):
                SQLiteStore.initialize(database)

    def test_permission_error_inspecting_database_is_storage_error(self):
        with TemporaryDirectory() as directory:
            database = Path(directory) / "inaccessible.sqlite3"
            with patch.object(Path, "stat", side_effect=PermissionError("denied")):
                with self.assertRaisesRegex(StorageError, "Could not inspect"):
                    SQLiteStore(database)
            self.assertFalse(database.exists())

    def test_corrupt_existing_database_is_not_classified_as_missing(self):
        with TemporaryDirectory() as directory:
            database = Path(directory) / "corrupt.sqlite3"
            database.write_bytes(b"not a SQLite database")

            with self.assertRaises(StorageError) as raised:
                SQLiteStore(database)

            self.assertNotIsInstance(raised.exception, DatabaseMissingError)
            self.assertTrue(database.is_file())

    def test_recursive_triggers_are_enabled_on_new_and_reopened_connections(self):
        with TemporaryDirectory() as directory:
            database = Path(directory) / "origin.sqlite3"
            with SQLiteStore.initialize(database):
                pass

            for _ in range(2):
                with SQLiteStore(database) as store:
                    enabled = store._connection.execute(
                        "PRAGMA recursive_triggers"
                    ).fetchone()[0]
                    self.assertEqual(enabled, 1)

    def test_replace_cannot_delete_an_event_when_recursive_triggers_are_on(self):
        with TemporaryDirectory() as directory:
            database = Path(directory) / "origin.sqlite3"

            with SQLiteStore.initialize(database) as store:
                store.record_event("original_event", {"value": 1})

            connection = sqlite3.connect(database)
            try:
                connection.execute("PRAGMA recursive_triggers = ON")
                with self.assertRaises(sqlite3.IntegrityError):
                    connection.execute(
                        """
                        INSERT OR REPLACE INTO system_events (
                            event_id, event_type, occurred_at_utc, payload_json
                        ) VALUES (1, 'replacement', '2026-01-01T00:00:00Z', '{}')
                        """
                    )
                event = connection.execute(
                    "SELECT event_type FROM system_events WHERE event_id = 1"
                ).fetchone()
                self.assertEqual(event[0], "original_event")
            finally:
                connection.close()

    def test_application_connection_rejects_replace_and_preserves_event(self):
        with TemporaryDirectory() as directory:
            database = Path(directory) / "origin.sqlite3"

            with SQLiteStore.initialize(database) as store:
                store.record_event("original_event", {"value": 1})

                recursive_triggers = store._connection.execute(
                    "PRAGMA recursive_triggers"
                ).fetchone()[0]
                self.assertEqual(recursive_triggers, 1)

                with self.assertRaises(sqlite3.IntegrityError):
                    store._connection.execute(
                        """
                        INSERT OR REPLACE INTO system_events (
                            event_id, event_type, occurred_at_utc, payload_json
                        ) VALUES (1, 'replacement', '2026-01-01T00:00:00Z', '{}')
                        """
                    )

                events = store.read_events()
                self.assertEqual(len(events), 1)
                self.assertEqual(events[0].event_type, "original_event")
                self.assertEqual(events[0].payload, {"value": 1})

    def test_upsert_update_is_rejected(self):
        with TemporaryDirectory() as directory:
            database = Path(directory) / "origin.sqlite3"
            with SQLiteStore.initialize(database) as store:
                store.record_event("original_event", {"value": 1})

            connection = sqlite3.connect(database)
            try:
                with self.assertRaises(sqlite3.IntegrityError):
                    connection.execute(
                        """
                        INSERT INTO system_events (
                            event_id, event_type, occurred_at_utc, payload_json
                        ) VALUES (1, 'replacement', '2026-01-01T00:00:00Z', '{}')
                        ON CONFLICT(event_id) DO UPDATE
                        SET event_type = excluded.event_type
                        """
                    )
            finally:
                connection.close()

    def test_ignored_insert_is_not_reported_as_success(self):
        with SQLiteStore.initialize(":memory:") as store:
            store._connection.execute(
                """
                CREATE TRIGGER test_ignore_insert
                BEFORE INSERT ON system_events
                WHEN NEW.event_type = 'ignored_event'
                BEGIN
                    SELECT RAISE(IGNORE);
                END
                """
            )
            with self.assertRaises(StorageError):
                store.record_event("ignored_event")
            self.assertEqual(store.read_events(), [])
            store._connection.execute("DROP TRIGGER test_ignore_insert")
            self.assertEqual(store.record_event("valid_event"), 1)

    def test_failed_insert_rolls_back_and_store_remains_usable(self):
        with SQLiteStore.initialize(":memory:") as store:
            store._connection.execute(
                """
                CREATE TRIGGER test_reject_insert
                BEFORE INSERT ON system_events
                WHEN NEW.event_type = 'rejected_event'
                BEGIN
                    SELECT RAISE(ABORT, 'injected write failure');
                END
                """
            )
            with self.assertRaises(StorageError):
                store.record_event("rejected_event")
            self.assertEqual(store.read_events(), [])
            store._connection.execute("DROP TRIGGER test_reject_insert")
            self.assertEqual(store.record_event("recovered_event"), 1)

    def test_commit_failure_rolls_back_and_does_not_return_event_id(self):
        with SQLiteStore.initialize(":memory:") as store:
            def deny_commit(action, argument1, argument2, database, trigger):
                if action == sqlite3.SQLITE_TRANSACTION and argument1 == "COMMIT":
                    return sqlite3.SQLITE_DENY
                return sqlite3.SQLITE_OK

            store._connection.set_authorizer(deny_commit)
            with self.assertRaises(StorageError):
                store.record_event("commit_failure")
            store._connection.set_authorizer(None)

            self.assertEqual(store.read_events(), [])
            self.assertEqual(store.record_event("after_commit_failure"), 1)

    def test_event_persists_after_reopening_database(self):
        with TemporaryDirectory() as directory:
            database = Path(directory) / "origin.sqlite3"

            with SQLiteStore.initialize(database) as store:
                event_id = store.record_event(
                    "startup_completed",
                    {"mode": "OBSERVE"},
                )
                self.assertEqual(event_id, 1)

            with SQLiteStore(database) as store:
                events = store.read_events()

                self.assertEqual(len(events), 1)
                self.assertEqual(events[0].event_type, "startup_completed")
                self.assertEqual(events[0].payload["mode"], "OBSERVE")
                self.assertTrue(events[0].occurred_at_utc.endswith("Z"))

    def test_invalid_payload_is_rejected(self):
        with SQLiteStore.initialize(":memory:") as store:
            with self.assertRaises(ValueError):
                store.record_event(
                    "invalid_event",
                    {"bad_value": object()},
                )

            self.assertEqual(store.read_events(), [])

    def test_newer_database_schema_is_rejected(self):
        with TemporaryDirectory() as directory:
            database = Path(directory) / "future.sqlite3"
            connection = sqlite3.connect(database)

            try:
                connection.execute("PRAGMA user_version = 999")
                connection.commit()
            finally:
                connection.close()

            with self.assertRaises(StorageError):
                SQLiteStore(database)

    def test_closed_database_rejects_operations(self):
        store = SQLiteStore.initialize(":memory:")
        store.close()

        with self.assertRaises(StorageError):
            store.read_events()

    def test_existing_events_cannot_be_updated(self):
        with TemporaryDirectory() as directory:
            database = Path(directory) / "origin.sqlite3"

            with SQLiteStore.initialize(database) as store:
                store.record_event("original_event", {"value": 1})

            connection = sqlite3.connect(database)

            try:
                with self.assertRaises(sqlite3.IntegrityError):
                    connection.execute(
                        """
                        UPDATE system_events
                        SET event_type = 'changed_event'
                        WHERE event_id = 1
                        """
                    )
            finally:
                connection.close()

    def test_existing_events_cannot_be_deleted(self):
        with TemporaryDirectory() as directory:
            database = Path(directory) / "origin.sqlite3"

            with SQLiteStore.initialize(database) as store:
                store.record_event("original_event", {"value": 1})

            connection = sqlite3.connect(database)

            try:
                with self.assertRaises(sqlite3.IntegrityError):
                    connection.execute(
                        "DELETE FROM system_events WHERE event_id = 1"
                    )
            finally:
                connection.close()

    def test_version_one_database_is_migrated_without_data_loss(self):
        with TemporaryDirectory() as directory:
            database = Path(directory) / "legacy.sqlite3"
            connection = sqlite3.connect(database)

            try:
                connection.execute(
                    """
                    CREATE TABLE system_events (
                        event_id INTEGER PRIMARY KEY AUTOINCREMENT,
                        event_type TEXT NOT NULL,
                        occurred_at_utc TEXT NOT NULL,
                        payload_json TEXT NOT NULL
                    )
                    """
                )

                connection.execute(
                    """
                    INSERT INTO system_events (
                        event_type,
                        occurred_at_utc,
                        payload_json
                    )
                    VALUES (?, ?, ?)
                    """,
                    ("legacy_event", "2026-01-01T00:00:00Z", '{"value":7}'),
                )

                connection.execute("PRAGMA user_version = 1")
                connection.commit()

            finally:
                connection.close()

            with SQLiteStore(database) as store:
                events = store.read_events()

                self.assertEqual(len(events), 1)
                self.assertEqual(events[0].event_type, "legacy_event")
                self.assertEqual(events[0].payload["value"], 7)

            connection = sqlite3.connect(database)

            try:
                version = connection.execute(
                    "PRAGMA user_version"
                ).fetchone()[0]

                self.assertEqual(version, SCHEMA_VERSION)

                with self.assertRaises(sqlite3.IntegrityError):
                    connection.execute(
                        "DELETE FROM system_events WHERE event_id = 1"
                    )

            finally:
                connection.close()

            backups = list(
                Path(directory).glob("legacy.sqlite3.v1-backup-*.sqlite3")
            )
            self.assertEqual(len(backups), 1)
            backup = sqlite3.connect(backups[0])
            try:
                self.assertEqual(
                    backup.execute("PRAGMA integrity_check").fetchone()[0],
                    "ok",
                )
                self.assertEqual(
                    backup.execute("PRAGMA user_version").fetchone()[0], 1
                )
                self.assertEqual(
                    backup.execute(
                        "SELECT event_type FROM system_events"
                    ).fetchone()[0],
                    "legacy_event",
                )
            finally:
                backup.close()

    def test_interrupted_migration_rolls_back_and_keeps_verified_backup(self):
        with TemporaryDirectory() as directory:
            database = Path(directory) / "legacy.sqlite3"
            connection = sqlite3.connect(database)
            try:
                connection.execute(
                    """
                    CREATE TABLE system_events (
                        event_id INTEGER PRIMARY KEY AUTOINCREMENT,
                        event_type TEXT NOT NULL,
                        occurred_at_utc TEXT NOT NULL,
                        payload_json TEXT NOT NULL
                    )
                    """
                )
                connection.execute(
                    """
                    INSERT INTO system_events (
                        event_type, occurred_at_utc, payload_json
                    ) VALUES ('legacy_event', '2026-01-01T00:00:00Z', '{}')
                    """
                )
                connection.execute("PRAGMA user_version = 1")
                connection.commit()
            finally:
                connection.close()

            original_verify = SQLiteStore._verify_schema

            def fail_after_schema_change(store, expected_version):
                if expected_version == SCHEMA_VERSION:
                    raise StorageError("injected migration interruption")
                return original_verify(store, expected_version)

            with patch.object(
                SQLiteStore, "_verify_schema", fail_after_schema_change
            ):
                with self.assertRaisesRegex(StorageError, "backup was retained"):
                    SQLiteStore(database)

            connection = sqlite3.connect(database)
            try:
                self.assertEqual(
                    connection.execute("PRAGMA user_version").fetchone()[0], 1
                )
                self.assertEqual(
                    connection.execute(
                        "SELECT event_type FROM system_events"
                    ).fetchone()[0],
                    "legacy_event",
                )
                names = {
                    row[0]
                    for row in connection.execute(
                        "SELECT name FROM sqlite_master WHERE type = 'table'"
                    )
                }
                self.assertIn("system_events", names)
                self.assertNotIn("system_events_v1_migration", names)
            finally:
                connection.close()

            backups = list(
                Path(directory).glob("legacy.sqlite3.v1-backup-*.sqlite3")
            )
            self.assertEqual(len(backups), 1)
            backup = sqlite3.connect(backups[0])
            try:
                self.assertEqual(
                    backup.execute("PRAGMA integrity_check").fetchone()[0],
                    "ok",
                )
                self.assertEqual(
                    backup.execute("PRAGMA user_version").fetchone()[0], 1
                )
                self.assertEqual(
                    backup.execute(
                        "SELECT event_type FROM system_events"
                    ).fetchone()[0],
                    "legacy_event",
                )
            finally:
                backup.close()

    def test_incorrect_trigger_definition_is_rejected(self):
        with TemporaryDirectory() as directory:
            database = Path(directory) / "tampered.sqlite3"

            with SQLiteStore.initialize(database):
                pass

            connection = sqlite3.connect(database)

            try:
                connection.execute(
                    "DROP TRIGGER system_events_reject_update"
                )

                connection.execute(
                    """
                    CREATE TRIGGER system_events_reject_update
                    BEFORE UPDATE ON system_events
                    BEGIN
                        SELECT 1;
                    END
                    """
                )

                connection.commit()
            finally:
                connection.close()

            with self.assertRaises(StorageError):
                SQLiteStore(database)

    def test_missing_required_trigger_is_rejected(self):
        with TemporaryDirectory() as directory:
            database = Path(directory) / "missing-trigger.sqlite3"
            with SQLiteStore.initialize(database):
                pass
            connection = sqlite3.connect(database)
            try:
                connection.execute("DROP TRIGGER system_events_reject_delete")
                connection.commit()
            finally:
                connection.close()
            with self.assertRaisesRegex(StorageError, "missing"):
                SQLiteStore(database)

    def test_unexpected_schema_object_is_rejected(self):
        with TemporaryDirectory() as directory:
            database = Path(directory) / "unexpected-object.sqlite3"
            with SQLiteStore.initialize(database):
                pass
            connection = sqlite3.connect(database)
            try:
                connection.execute(
                    "CREATE VIEW unexpected_events AS SELECT * FROM system_events"
                )
                connection.commit()
            finally:
                connection.close()
            with self.assertRaisesRegex(StorageError, "unexpected"):
                SQLiteStore(database)

    def test_unexpected_trigger_is_rejected_when_database_is_reopened(self):
        with TemporaryDirectory() as directory:
            database = Path(directory) / "unexpected-trigger.sqlite3"
            with SQLiteStore.initialize(database):
                pass

            connection = sqlite3.connect(database)
            try:
                connection.execute(
                    """
                    CREATE TRIGGER unexpected_event_trigger
                    BEFORE INSERT ON system_events
                    BEGIN
                        SELECT RAISE(ABORT, 'unexpected trigger');
                    END
                    """
                )
                connection.commit()
            finally:
                connection.close()

            with self.assertRaisesRegex(StorageError, "unexpected"):
                SQLiteStore(database)

    def test_altered_table_definition_is_rejected(self):
        with TemporaryDirectory() as directory:
            database = Path(directory) / "altered-table.sqlite3"
            with SQLiteStore.initialize(database):
                pass
            connection = sqlite3.connect(database)
            try:
                connection.execute(
                    "ALTER TABLE system_events RENAME COLUMN event_type TO event_name"
                )
                connection.commit()
            finally:
                connection.close()
            with self.assertRaises(StorageError):
                SQLiteStore(database)


if __name__ == "__main__":
    unittest.main()
