import json
import sqlite3
from concurrent.futures import ThreadPoolExecutor
import subprocess
import sys
import textwrap
from threading import Barrier
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest.mock import patch
from uuid import uuid4

from origin_trader.storage.sqlite_store import (
    DatabaseMissingError,
    IdempotencyConflictError,
    SCHEMA_VERSION,
    SQLiteStore,
    StorageError,
)


def _record(store, event_type, payload=None):
    """Submit a test event with a fresh valid key unless a test needs reuse."""
    return store.record_event(event_type, payload, f"test:{uuid4()}")


class StorageTests(unittest.TestCase):

    def _source_path(self):
        return str(Path(__file__).resolve().parents[1] / "src")

    def _run_competing_submissions(self, database, key, submissions):
        with TemporaryDirectory() as directory:
            ready_dir = Path(directory)
            script = textwrap.dedent(
                """
                import json, pathlib, sys, time
                sys.path.insert(0, sys.argv[1])
                from origin_trader.storage.sqlite_store import (
                    IdempotencyConflictError, SQLiteStore
                )
                database, key, event_type, payload_text, ready_dir, label = sys.argv[2:]
                ready = pathlib.Path(ready_dir)
                store = SQLiteStore(database)
                (ready / (label + '.ready')).write_text('ready')
                deadline = time.monotonic() + 15
                while len(list(ready.glob('*.ready'))) < 2:
                    if time.monotonic() >= deadline:
                        raise TimeoutError('concurrent start barrier timed out')
                    time.sleep(0.01)
                try:
                    event_id = store.record_event(
                        event_type, json.loads(payload_text), key
                    )
                    print(json.dumps({'result': 'ok', 'event_id': event_id}))
                except IdempotencyConflictError:
                    print(json.dumps({'result': 'conflict'}))
                finally:
                    store.close()
                """
            )
            processes = [
                subprocess.Popen(
                    [
                        sys.executable,
                        "-c",
                        script,
                        self._source_path(),
                        str(database),
                        key,
                        event_type,
                        json.dumps(payload),
                        str(ready_dir),
                        str(index),
                    ],
                    cwd=str(Path(__file__).resolve().parents[1]),
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    text=True,
                )
                for index, (event_type, payload) in enumerate(submissions)
            ]
            outcomes = []
            for process in processes:
                stdout, stderr = process.communicate(timeout=25)
                self.assertEqual(process.returncode, 0, stderr)
                outcomes.append(json.loads(stdout.strip().splitlines()[-1]))
            return outcomes

    def test_idempotent_repeat_returns_same_event_for_canonical_payload(self):
        key = f"test:{uuid4()}"
        with SQLiteStore.initialize(":memory:") as store:
            first_id = store.record_event("same_event", {"a": 1, "b": 2}, key)
            repeated_id = store.record_event("same_event", {"b": 2, "a": 1}, key)

            self.assertEqual(repeated_id, first_id)
            events = store.read_events()
            self.assertEqual(len(events), 1)
            self.assertEqual(events[0].idempotency_key, key)

    def test_idempotency_key_reuse_with_different_event_type_or_payload_fails(self):
        key = f"test:{uuid4()}"
        with SQLiteStore.initialize(":memory:") as store:
            event_id = store.record_event("original", {"value": 1}, key)

            with self.assertRaises(IdempotencyConflictError):
                store.record_event("different_type", {"value": 1}, key)
            with self.assertRaises(IdempotencyConflictError):
                store.record_event("original", {"value": 2}, key)
            self.assertFalse(store._connection.in_transaction)

            unrelated_id = store.record_event(
                "unrelated_event", {"value": 3}, f"test:{uuid4()}"
            )

            events = store.read_events()
            self.assertEqual(len(events), 2)
            self.assertEqual(events[0].event_id, event_id)
            self.assertEqual(events[0].event_type, "original")
            self.assertEqual(events[0].payload, {"value": 1})
            self.assertEqual(events[1].event_id, unrelated_id)
            self.assertEqual(events[1].event_type, "unrelated_event")

    def test_idempotency_survives_close_and_reopen(self):
        with TemporaryDirectory() as directory:
            database = Path(directory) / "idempotent.sqlite3"
            key = f"test:{uuid4()}"
            with SQLiteStore.initialize(database) as store:
                event_id = store.record_event("restart_event", {"x": 1}, key)
            with SQLiteStore(database) as store:
                repeated_id = store.record_event("restart_event", {"x": 1}, key)
                self.assertEqual(repeated_id, event_id)
                self.assertEqual(len(store.read_events()), 1)

    def test_invalid_idempotency_keys_are_rejected(self):
        invalid_keys = [
            "Test:550e8400-e29b-41d4-a716-446655440000",
            "test :550e8400-e29b-41d4-a716-446655440000",
            "test:550E8400-e29b-41d4-a716-446655440000",
            "test:550e8400e29b41d4a716446655440000",
            "1test:550e8400-e29b-41d4-a716-446655440000",
            "test-" + ("a" * 49) + ":550e8400-e29b-41d4-a716-446655440000",
            "test:550e8400-e29b-41d4-a716-446655440000\n",
        ]
        with SQLiteStore.initialize(":memory:") as store:
            for key in invalid_keys:
                with self.subTest(key=key), self.assertRaises(ValueError):
                    store.record_event("invalid_key", {}, key)
            self.assertEqual(store.read_events(), [])

    def test_idempotency_key_argument_is_required(self):
        with SQLiteStore.initialize(":memory:") as store:
            with self.assertRaises(TypeError):
                store.record_event("missing_key", {})

    def test_database_trigger_rejects_missing_or_invalid_idempotency_key(self):
        valid_uuid = "550e8400-e29b-41d4-a716-446655440000"
        invalid_keys = [
            "test:" + valid_uuid + "\x00trailing",
            "test:550E8400-e29b-41d4-a716-446655440000",
            "test:" + valid_uuid + ":extra",
            "test :" + valid_uuid,
            "test:not-a-valid-uuid",
            "bad_namespace:" + valid_uuid,
        ]
        with SQLiteStore.initialize(":memory:") as store:
            candidates = [(None, "null key"), ("invalid-key", "malformed key")]
            candidates.extend((key, key) for key in invalid_keys)
            candidates.append(
                (sqlite3.Binary(b"test:" + valid_uuid.encode("ascii")), "BLOB key")
            )

            for key, label in candidates:
                with self.subTest(key=label), self.assertRaises(sqlite3.IntegrityError):
                    store._connection.execute(
                        """
                        INSERT INTO system_events (
                            event_type, occurred_at_utc, payload_json, idempotency_key
                        ) VALUES ('raw_event', '2026-01-01T00:00:00Z', '{}', ?)
                        """,
                        (key,),
                    )
            self.assertEqual(store.read_events(), [])

    def test_schema_v3_exact_idempotency_definitions_open_successfully(self):
        with TemporaryDirectory() as directory:
            database = Path(directory) / "verified-v3.sqlite3"
            with SQLiteStore.initialize(database):
                pass
            with SQLiteStore(database) as store:
                store._verify_schema(expected_version=SCHEMA_VERSION)

    def test_unique_partial_index_rejects_duplicate_non_null_key(self):
        key = f"test:{uuid4()}"
        with SQLiteStore.initialize(":memory:") as store:
            store._connection.execute(
                """
                INSERT INTO system_events (
                    event_type, occurred_at_utc, payload_json, idempotency_key
                ) VALUES ('raw_event', '2026-01-01T00:00:00Z', '{}', ?)
                """,
                (key,),
            )
            with self.assertRaises(sqlite3.IntegrityError):
                store._connection.execute(
                    """
                    INSERT INTO system_events (
                        event_type, occurred_at_utc, payload_json, idempotency_key
                    ) VALUES ('raw_event', '2026-01-01T00:00:01Z', '{}', ?)
                    """,
                    (key,),
                )
            self.assertEqual(len(store.read_events()), 1)

    def test_concurrent_processes_with_same_key_create_one_event(self):
        with TemporaryDirectory() as directory:
            database = Path(directory) / "concurrent.sqlite3"
            key = f"test:{uuid4()}"
            with SQLiteStore.initialize(database):
                pass
            outcomes = self._run_competing_submissions(
                database,
                key,
                [
                    ("concurrent_event", {"value": 1}),
                    ("concurrent_event", {"value": 1}),
                ],
            )
            self.assertEqual([result["result"] for result in outcomes], ["ok", "ok"])
            self.assertEqual(outcomes[0]["event_id"], outcomes[1]["event_id"])
            with SQLiteStore(database) as store:
                self.assertEqual(len(store.read_events()), 1)

    def test_concurrent_processes_with_conflicting_content_return_one_conflict(self):
        with TemporaryDirectory() as directory:
            database = Path(directory) / "conflicting.sqlite3"
            key = f"test:{uuid4()}"
            with SQLiteStore.initialize(database):
                pass
            outcomes = self._run_competing_submissions(
                database,
                key,
                [
                    ("concurrent_event", {"value": 1}),
                    ("concurrent_event", {"value": 2}),
                ],
            )
            self.assertCountEqual(
                [result["result"] for result in outcomes], ["ok", "conflict"]
            )
            with SQLiteStore(database) as store:
                self.assertEqual(len(store.read_events()), 1)

    def test_subprocess_lost_acknowledgement_retry_returns_committed_event(self):
        with TemporaryDirectory() as directory:
            database = Path(directory) / "lost-ack.sqlite3"
            key = f"test:{uuid4()}"
            with SQLiteStore.initialize(database):
                pass
            script = textwrap.dedent(
                """
                import os, sys
                sys.path.insert(0, sys.argv[1])
                from origin_trader.storage.sqlite_store import SQLiteStore
                store = SQLiteStore(sys.argv[2])
                store.record_event('lost_ack', {'value': 1}, sys.argv[3])
                os._exit(73)
                """
            )
            process = subprocess.run(
                [sys.executable, "-c", script, self._source_path(), str(database), key],
                cwd=str(Path(__file__).resolve().parents[1]),
                capture_output=True,
                text=True,
                timeout=20,
            )
            self.assertEqual(process.returncode, 73)
            with SQLiteStore(database) as store:
                event_id = store.record_event("lost_ack", {"value": 1}, key)
                self.assertEqual(len(store.read_events()), 1)
                self.assertEqual(store.read_events()[0].event_id, event_id)

    def test_subprocess_termination_before_commit_leaves_key_available(self):
        with TemporaryDirectory() as directory:
            database = Path(directory) / "before-commit.sqlite3"
            key = f"test:{uuid4()}"
            with SQLiteStore.initialize(database):
                pass
            script = textwrap.dedent(
                """
                import os, sys
                sys.path.insert(0, sys.argv[1])
                from origin_trader.storage.sqlite_store import SQLiteStore
                store = SQLiteStore(sys.argv[2])
                store._connection.create_function('crash_now', 0, lambda: os._exit(74))
                store._connection.execute('''
                    CREATE TEMP TRIGGER terminate_before_commit
                    AFTER INSERT ON system_events
                    BEGIN SELECT crash_now(); END
                ''')
                store.record_event('before_commit', {'value': 1}, sys.argv[3])
                """
            )
            process = subprocess.run(
                [sys.executable, "-c", script, self._source_path(), str(database), key],
                cwd=str(Path(__file__).resolve().parents[1]),
                capture_output=True,
                text=True,
                timeout=20,
            )
            self.assertEqual(process.returncode, 74, process.stderr)
            with SQLiteStore(database) as store:
                event_id = store.record_event("before_commit", {"value": 1}, key)
                events = store.read_events()
                self.assertEqual(len(events), 1)
                self.assertEqual(events[0].event_id, event_id)

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

    def test_new_file_uses_verified_wal_full_and_connection_policy(self):
        with TemporaryDirectory() as directory:
            database = Path(directory) / "origin.sqlite3"
            with SQLiteStore.initialize(database) as store:
                connection = store._connection
                self.assertEqual(connection.execute("PRAGMA journal_mode").fetchone()[0], "wal")
                self.assertEqual(connection.execute("PRAGMA synchronous").fetchone()[0], 2)
                self.assertEqual(connection.execute("PRAGMA wal_autocheckpoint").fetchone()[0], 1000)
                self.assertEqual(connection.execute("PRAGMA locking_mode").fetchone()[0], "normal")
                self.assertEqual(connection.execute("PRAGMA busy_timeout").fetchone()[0], 5000)
                self.assertEqual(connection.execute("PRAGMA foreign_keys").fetchone()[0], 1)
                self.assertEqual(connection.execute("PRAGMA recursive_triggers").fetchone()[0], 1)
                self.assertEqual(connection.execute("PRAGMA user_version").fetchone()[0], 4)

    def test_in_memory_store_retains_memory_journal_mode(self):
        with SQLiteStore.initialize(":memory:") as store:
            self.assertEqual(
                store._connection.execute("PRAGMA journal_mode").fetchone()[0],
                "memory",
            )
            self.assertEqual(store._connection.execute("PRAGMA synchronous").fetchone()[0], 2)
            self.assertEqual(store._connection.execute("PRAGMA wal_autocheckpoint").fetchone()[0], 1000)

    def test_v4_open_rejects_unexpected_journal_mode_without_changing_it(self):
        with TemporaryDirectory() as directory:
            database = Path(directory) / "origin.sqlite3"
            with SQLiteStore.initialize(database):
                pass
            connection = sqlite3.connect(database)
            try:
                self.assertEqual(connection.execute("PRAGMA journal_mode=DELETE").fetchone()[0], "delete")
            finally:
                connection.close()
            with self.assertRaisesRegex(StorageError, "journal mode"):
                SQLiteStore(database)
            connection = sqlite3.connect(database)
            try:
                self.assertEqual(connection.execute("PRAGMA journal_mode").fetchone()[0], "delete")
            finally:
                connection.close()

    def test_v4_open_rejects_unsupported_journal_mode(self):
        with TemporaryDirectory() as directory:
            database = Path(directory) / "origin.sqlite3"
            with SQLiteStore.initialize(database):
                pass
            connection = sqlite3.connect(database)
            try:
                self.assertEqual(connection.execute("PRAGMA journal_mode=MEMORY").fetchone()[0], "memory")
            finally:
                connection.close()
            with self.assertRaisesRegex(StorageError, "journal mode"):
                SQLiteStore(database)

    def test_independent_store_connections_apply_full_configuration(self):
        with TemporaryDirectory() as directory:
            database = Path(directory) / "origin.sqlite3"
            with SQLiteStore.initialize(database):
                pass
            first = SQLiteStore(database)
            second = SQLiteStore(database)
            try:
                for store in (first, second):
                    connection = store._connection
                    self.assertEqual(connection.execute("PRAGMA journal_mode").fetchone()[0], "wal")
                    self.assertEqual(connection.execute("PRAGMA synchronous").fetchone()[0], 2)
                    self.assertEqual(connection.execute("PRAGMA wal_autocheckpoint").fetchone()[0], 1000)
            finally:
                first.close()
                second.close()

    def test_separate_process_applies_full_connection_configuration(self):
        with TemporaryDirectory() as directory:
            database = Path(directory) / "origin.sqlite3"
            with SQLiteStore.initialize(database):
                pass
            script = textwrap.dedent(
                """
                import json, sys
                sys.path.insert(0, sys.argv[1])
                from origin_trader.storage.sqlite_store import SQLiteStore
                store = SQLiteStore(sys.argv[2])
                values = [
                    store._connection.execute('PRAGMA journal_mode').fetchone()[0],
                    store._connection.execute('PRAGMA synchronous').fetchone()[0],
                    store._connection.execute('PRAGMA wal_autocheckpoint').fetchone()[0],
                ]
                print(json.dumps(values))
                store.close()
                """
            )
            result = subprocess.run(
                [sys.executable, "-c", script, self._source_path(), str(database)],
                cwd=str(Path(__file__).resolve().parents[1]),
                capture_output=True,
                text=True,
                timeout=20,
            )
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(json.loads(result.stdout), ["wal", 2, 1000])

    def test_lock_timeout_rejects_event_without_partial_write(self):
        with TemporaryDirectory() as directory:
            database = Path(directory) / "origin.sqlite3"
            with SQLiteStore.initialize(database) as store:
                blocker = sqlite3.connect(database, isolation_level=None)
                try:
                    blocker.execute("BEGIN IMMEDIATE")
                    with self.assertRaises(StorageError):
                        _record(store, "blocked_write")
                    self.assertEqual(store.read_events(), [])
                finally:
                    blocker.execute("ROLLBACK")
                    blocker.close()
                self.assertEqual(_record(store, "after_lock_release"), 1)

    def test_backup_during_concurrent_writes_is_a_valid_snapshot(self):
        with TemporaryDirectory() as directory:
            database = Path(directory) / "origin.sqlite3"
            with SQLiteStore.initialize(database) as store:
                _record(store, "initial_event")
                start_writes = Barrier(2)

                def write_events():
                    with SQLiteStore(database) as writer:
                        start_writes.wait()
                        for index in range(100):
                            _record(writer, "concurrent_event", {"index": index})

                with ThreadPoolExecutor(max_workers=1) as pool:
                    writer = pool.submit(write_events)
                    start_writes.wait()
                    backup_path = store._create_verified_backup(database, version=4)
                    writer.result(timeout=20)

                backup = sqlite3.connect(backup_path)
                try:
                    self.assertEqual(backup.execute("PRAGMA journal_mode").fetchone()[0], "wal")
                    self.assertEqual(backup.execute("PRAGMA integrity_check").fetchone()[0], "ok")
                    self.assertEqual(backup.execute("PRAGMA user_version").fetchone()[0], 4)
                    count = backup.execute("SELECT COUNT(*) FROM system_events").fetchone()[0]
                    self.assertGreaterEqual(count, 1)
                    self.assertLessEqual(count, 101)
                finally:
                    backup.close()

    def test_backup_verification_rejects_unexpected_journal_mode(self):
        with TemporaryDirectory() as directory:
            database = Path(directory) / "origin.sqlite3"
            with SQLiteStore.initialize(database) as store:
                original = SQLiteStore._configure_connection
                calls = 0

                def change_reopened_backup_mode(instance):
                    nonlocal calls
                    calls += 1
                    if calls == 2:
                        instance._connection.execute("PRAGMA journal_mode=DELETE")
                    return original(instance)

                with patch.object(
                    SQLiteStore,
                    "_configure_connection",
                    change_reopened_backup_mode,
                ):
                    with self.assertRaisesRegex(StorageError, "create and verify"):
                        store._create_verified_backup(database, version=4)

            backups = list(Path(directory).glob("origin.sqlite3.v4-backup-*.sqlite3"))
            self.assertEqual(len(backups), 1)
            backup = sqlite3.connect(backups[0])
            try:
                self.assertEqual(
                    backup.execute("PRAGMA journal_mode").fetchone()[0],
                    "delete",
                )
            finally:
                backup.close()

    def test_real_reader_lock_blocks_wal_transition_and_retry_succeeds(self):
        with TemporaryDirectory() as directory:
            database = Path(directory) / "legacy-v3.sqlite3"
            with SQLiteStore.initialize(database) as store:
                _record(store, "legacy_event", {"preserve": True})
                store._connection.execute("PRAGMA user_version=3")
            connection = sqlite3.connect(database)
            try:
                self.assertEqual(
                    connection.execute("PRAGMA journal_mode=DELETE").fetchone()[0],
                    "delete",
                )
                connection.execute("PRAGMA user_version=3")
                connection.commit()
            finally:
                connection.close()

            reader = sqlite3.connect(database, isolation_level=None)
            try:
                reader.execute("BEGIN")
                reader.execute("SELECT COUNT(*) FROM system_events").fetchone()

                with self.assertRaisesRegex(StorageError, "safely open database"):
                    SQLiteStore(database)

                connection = sqlite3.connect(database)
                try:
                    self.assertEqual(
                        connection.execute("PRAGMA user_version").fetchone()[0],
                        3,
                    )
                    self.assertEqual(
                        connection.execute("PRAGMA journal_mode").fetchone()[0],
                        "delete",
                    )
                finally:
                    connection.close()

                backups = list(
                    Path(directory).glob("legacy-v3.sqlite3.v3-backup-*.sqlite3")
                )
                self.assertEqual(len(backups), 1)
                backup = sqlite3.connect(backups[0])
                try:
                    self.assertEqual(
                        backup.execute("PRAGMA user_version").fetchone()[0], 3
                    )
                    self.assertEqual(
                        backup.execute("PRAGMA integrity_check").fetchone()[0],
                        "ok",
                    )
                    self.assertEqual(
                        backup.execute(
                            "SELECT event_type FROM system_events"
                        ).fetchone()[0],
                        "legacy_event",
                    )
                finally:
                    backup.close()
            finally:
                if reader.in_transaction:
                    reader.execute("ROLLBACK")
                reader.close()

            with SQLiteStore(database) as store:
                self.assertEqual(
                    store._connection.execute("PRAGMA user_version").fetchone()[0],
                    4,
                )
                self.assertEqual(
                    store._connection.execute("PRAGMA journal_mode").fetchone()[0],
                    "wal",
                )
                events = store.read_events()
                self.assertEqual(len(events), 1)
                self.assertEqual(events[0].event_type, "legacy_event")

    def test_v3_wal_policy_migration_preserves_history_and_backup(self):
        with TemporaryDirectory() as directory:
            database = Path(directory) / "legacy-v3.sqlite3"
            with SQLiteStore.initialize(database) as store:
                _record(store, "before_v4", {"preserve": True})
                store._connection.execute("PRAGMA user_version=3")
            with SQLiteStore(database) as store:
                events = store.read_events()
                self.assertEqual(len(events), 1)
                self.assertEqual(events[0].event_type, "before_v4")
                self.assertIsNotNone(events[0].idempotency_key)
                self.assertEqual(store._connection.execute("PRAGMA user_version").fetchone()[0], 4)
            backups = list(Path(directory).glob("legacy-v3.sqlite3.v3-backup-*.sqlite3"))
            self.assertEqual(len(backups), 1)
            backup = sqlite3.connect(backups[0])
            try:
                self.assertEqual(backup.execute("PRAGMA user_version").fetchone()[0], 3)
                self.assertEqual(backup.execute("PRAGMA journal_mode").fetchone()[0], "wal")
                self.assertEqual(backup.execute("SELECT COUNT(*) FROM system_events").fetchone()[0], 1)
            finally:
                backup.close()

    def test_legacy_already_in_wal_mode_migrates(self):
        with TemporaryDirectory() as directory:
            database = Path(directory) / "legacy-v3.sqlite3"
            with SQLiteStore.initialize(database):
                pass
            connection = sqlite3.connect(database)
            try:
                connection.execute("PRAGMA journal_mode=DELETE")
                connection.execute("PRAGMA user_version=3")
                connection.commit()
                self.assertEqual(connection.execute("PRAGMA journal_mode=WAL").fetchone()[0], "wal")
            finally:
                connection.close()
            with SQLiteStore(database) as store:
                self.assertEqual(store._connection.execute("PRAGMA user_version").fetchone()[0], 4)

    def test_v3_transition_failure_keeps_legacy_schema_and_fails_closed(self):
        with TemporaryDirectory() as directory:
            database = Path(directory) / "legacy-v3.sqlite3"
            with SQLiteStore.initialize(database):
                pass
            connection = sqlite3.connect(database)
            try:
                connection.execute("PRAGMA journal_mode=DELETE")
                connection.execute("PRAGMA user_version=3")
                connection.commit()
            finally:
                connection.close()

            original = SQLiteStore._configure_durability

            def fail_main_transition(instance, *, allow_transition=False):
                if allow_transition and getattr(instance, "_database_path", None) is not None:
                    raise StorageError("injected WAL transition failure")
                return original(instance, allow_transition=allow_transition)

            with patch.object(SQLiteStore, "_configure_durability", fail_main_transition):
                with self.assertRaisesRegex(StorageError, "injected WAL transition failure"):
                    SQLiteStore(database)
            connection = sqlite3.connect(database)
            try:
                self.assertEqual(connection.execute("PRAGMA user_version").fetchone()[0], 3)
                self.assertEqual(connection.execute("PRAGMA journal_mode").fetchone()[0], "delete")
            finally:
                connection.close()

    def test_restart_resumes_after_wal_transition_before_schema_commit(self):
        with TemporaryDirectory() as directory:
            database = Path(directory) / "legacy-v3.sqlite3"
            with SQLiteStore.initialize(database):
                pass
            connection = sqlite3.connect(database)
            try:
                connection.execute("PRAGMA journal_mode=DELETE")
                connection.execute("PRAGMA user_version=3")
                connection.commit()
            finally:
                connection.close()

            with patch.object(
                SQLiteStore,
                "_migrate_v3_to_v4",
                side_effect=StorageError("injected stop after WAL transition"),
            ):
                with self.assertRaisesRegex(StorageError, "injected stop"):
                    SQLiteStore(database)

            connection = sqlite3.connect(database)
            try:
                self.assertEqual(connection.execute("PRAGMA user_version").fetchone()[0], 3)
                self.assertEqual(connection.execute("PRAGMA journal_mode").fetchone()[0], "wal")
            finally:
                connection.close()
            with SQLiteStore(database) as store:
                self.assertEqual(store._connection.execute("PRAGMA user_version").fetchone()[0], 4)

    def test_passive_checkpoint_waits_for_reader_then_completes(self):
        with TemporaryDirectory() as directory:
            database = Path(directory) / "origin.sqlite3"
            with SQLiteStore.initialize(database) as store:
                _record(store, "reader_snapshot")
                reader = sqlite3.connect(database, isolation_level=None)
                try:
                    reader.execute("BEGIN")
                    reader.execute("SELECT COUNT(*) FROM system_events").fetchone()
                    _record(store, "after_reader_snapshot")
                    busy, log_frames, checkpointed = store._connection.execute(
                        "PRAGMA wal_checkpoint(PASSIVE)"
                    ).fetchone()
                    self.assertGreater(log_frames, 0)
                    self.assertLess(checkpointed, log_frames)
                    reader.execute("COMMIT")
                    busy, log_frames, checkpointed = store._connection.execute(
                        "PRAGMA wal_checkpoint(FULL)"
                    ).fetchone()
                    self.assertEqual(busy, 0)
                    self.assertEqual(checkpointed, log_frames)
                finally:
                    reader.close()

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
                _record(store, "historical_event", {"value": 7})

            database.unlink()
            with self.assertRaises(DatabaseMissingError):
                SQLiteStore(database)
            self.assertFalse(database.exists())

    def test_initialization_refuses_existing_database_without_overwriting(self):
        with TemporaryDirectory() as directory:
            database = Path(directory) / "existing.sqlite3"
            with SQLiteStore.initialize(database) as store:
                _record(store, "preserve_me", {"value": 9})

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
                        _record(store, "winning_initialization")
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
                _record(store, "original_event", {"value": 1})

            connection = sqlite3.connect(database)
            try:
                connection.execute("PRAGMA recursive_triggers = ON")
                with self.assertRaises(sqlite3.IntegrityError):
                    connection.execute(
                        """
                        INSERT OR REPLACE INTO system_events (
                            event_id, event_type, occurred_at_utc, payload_json,
                            idempotency_key
                        ) VALUES (1, 'replacement', '2026-01-01T00:00:00Z', '{}',
                                  'test:550e8400-e29b-41d4-a716-446655440000')
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
                _record(store, "original_event", {"value": 1})

                recursive_triggers = store._connection.execute(
                    "PRAGMA recursive_triggers"
                ).fetchone()[0]
                self.assertEqual(recursive_triggers, 1)

                with self.assertRaises(sqlite3.IntegrityError):
                    store._connection.execute(
                        """
                        INSERT OR REPLACE INTO system_events (
                            event_id, event_type, occurred_at_utc, payload_json,
                            idempotency_key
                        ) VALUES (1, 'replacement', '2026-01-01T00:00:00Z', '{}',
                                  'test:550e8400-e29b-41d4-a716-446655440000')
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
                _record(store, "original_event", {"value": 1})

            connection = sqlite3.connect(database)
            try:
                with self.assertRaises(sqlite3.IntegrityError):
                    connection.execute(
                        """
                        INSERT INTO system_events (
                            event_id, event_type, occurred_at_utc, payload_json,
                            idempotency_key
                        ) VALUES (1, 'replacement', '2026-01-01T00:00:00Z', '{}',
                                  'test:550e8400-e29b-41d4-a716-446655440000')
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
                _record(store, "ignored_event")
            self.assertEqual(store.read_events(), [])
            store._connection.execute("DROP TRIGGER test_ignore_insert")
            self.assertEqual(_record(store, "valid_event"), 1)

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
                _record(store, "rejected_event")
            self.assertEqual(store.read_events(), [])
            store._connection.execute("DROP TRIGGER test_reject_insert")
            self.assertEqual(_record(store, "recovered_event"), 1)

    def test_commit_failure_rolls_back_and_does_not_return_event_id(self):
        with SQLiteStore.initialize(":memory:") as store:
            def deny_commit(action, argument1, argument2, database, trigger):
                if action == sqlite3.SQLITE_TRANSACTION and argument1 == "COMMIT":
                    return sqlite3.SQLITE_DENY
                return sqlite3.SQLITE_OK

            store._connection.set_authorizer(deny_commit)
            with self.assertRaises(StorageError):
                _record(store, "commit_failure")
            store._connection.set_authorizer(None)

            self.assertEqual(store.read_events(), [])
            self.assertEqual(_record(store, "after_commit_failure"), 1)

    def test_event_persists_after_reopening_database(self):
        with TemporaryDirectory() as directory:
            database = Path(directory) / "origin.sqlite3"

            with SQLiteStore.initialize(database) as store:
                event_id = _record(
                    store,
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
                _record(
                    store,
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
                _record(store, "original_event", {"value": 1})

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
                _record(store, "original_event", {"value": 1})

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
                self.assertIsNone(events[0].idempotency_key)
                self.assertEqual(
                    store._connection.execute("PRAGMA journal_mode").fetchone()[0],
                    "wal",
                )
                self.assertEqual(
                    store._connection.execute("PRAGMA synchronous").fetchone()[0],
                    2,
                )

            connection = sqlite3.connect(database)

            try:
                version = connection.execute(
                    "PRAGMA user_version"
                ).fetchone()[0]

                self.assertEqual(version, SCHEMA_VERSION)
                self.assertEqual(
                    connection.execute(
                        "SELECT idempotency_key FROM system_events WHERE event_id = 1"
                    ).fetchone()[0],
                    None,
                )

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

    def test_version_two_database_is_migrated_without_data_loss(self):
        with TemporaryDirectory() as directory:
            database = Path(directory) / "legacy-v2.sqlite3"
            connection = sqlite3.connect(database)
            try:
                connection.execute(
                    """
                    CREATE TABLE system_events (
                        event_id INTEGER PRIMARY KEY AUTOINCREMENT,
                        event_type TEXT NOT NULL CHECK(length(trim(event_type)) > 0),
                        occurred_at_utc TEXT NOT NULL,
                        payload_json TEXT NOT NULL
                    )
                    """
                )
                connection.execute(
                    """
                    INSERT INTO system_events (
                        event_id, event_type, occurred_at_utc, payload_json
                    ) VALUES (7, 'legacy_v2', '2026-01-02T00:00:00Z', '{"n":2}')
                    """
                )
                connection.executescript(
                    """
                    CREATE TRIGGER system_events_reject_update
                    BEFORE UPDATE ON system_events
                    BEGIN SELECT RAISE(ABORT, 'system_events is append-only'); END;
                    CREATE TRIGGER system_events_reject_delete
                    BEFORE DELETE ON system_events
                    BEGIN SELECT RAISE(ABORT, 'system_events is append-only'); END;
                    PRAGMA user_version = 2;
                    """
                )
                connection.commit()
            finally:
                connection.close()

            with SQLiteStore(database) as store:
                events = store.read_events()
                self.assertEqual(len(events), 1)
                self.assertEqual(events[0].event_id, 7)
                self.assertEqual(events[0].event_type, "legacy_v2")
                self.assertEqual(events[0].occurred_at_utc, "2026-01-02T00:00:00Z")
                self.assertEqual(events[0].payload, {"n": 2})
                self.assertIsNone(events[0].idempotency_key)
                self.assertEqual(
                    store._connection.execute("PRAGMA journal_mode").fetchone()[0],
                    "wal",
                )
                self.assertEqual(
                    store._connection.execute("PRAGMA synchronous").fetchone()[0],
                    2,
                )

            backups = list(
                Path(directory).glob("legacy-v2.sqlite3.v2-backup-*.sqlite3")
            )
            self.assertEqual(len(backups), 1)
            backup = sqlite3.connect(backups[0])
            try:
                self.assertEqual(backup.execute("PRAGMA user_version").fetchone()[0], 2)
                self.assertEqual(backup.execute("PRAGMA journal_mode").fetchone()[0], "wal")
                self.assertEqual(
                    backup.execute("SELECT event_id FROM system_events").fetchone()[0],
                    7,
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
