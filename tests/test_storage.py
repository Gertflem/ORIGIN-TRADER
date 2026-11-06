import sqlite3
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory

from origin_trader.storage.sqlite_store import (
    SCHEMA_VERSION,
    SQLiteStore,
    StorageError,
)


class StorageTests(unittest.TestCase):

    def test_database_is_created_with_correct_schema(self):
        with TemporaryDirectory() as directory:
            database = Path(directory) / "origin.sqlite3"

            with SQLiteStore(database):
                self.assertTrue(database.exists())

            connection = sqlite3.connect(database)

            try:
                version = connection.execute(
                    "PRAGMA user_version"
                ).fetchone()[0]

                self.assertEqual(version, SCHEMA_VERSION)

            finally:
                connection.close()

    def test_event_persists_after_reopening_database(self):
        with TemporaryDirectory() as directory:
            database = Path(directory) / "origin.sqlite3"

            with SQLiteStore(database) as store:
                event_id = store.record_event(
                    "startup_completed",
                    {"mode": "OBSERVE"},
                )

                self.assertEqual(event_id, 1)

            with SQLiteStore(database) as store:
                events = store.read_events()

                self.assertEqual(len(events), 1)
                self.assertEqual(events[0].event_type, "startup_completed")
                self.assertEqual(
                    events[0].payload["mode"],
                    "OBSERVE",
                )
                self.assertTrue(
                    events[0].occurred_at_utc.endswith("Z")
                )

    def test_invalid_payload_is_rejected(self):
        with SQLiteStore(":memory:") as store:
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
        store = SQLiteStore(":memory:")
        store.close()

        with self.assertRaises(StorageError):
            store.read_events()


if __name__ == "__main__":
    unittest.main()