import json
import sqlite3
from concurrent.futures import ThreadPoolExecutor
import subprocess
import sys
import textwrap
import time
from threading import Barrier, Event
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


class FaultInjectingConnection:
    """Connection proxy for deterministic SQLite failure-path tests."""

    def __init__(
        self,
        connection,
        *,
        execute_failure=None,
        execute_match=None,
        commit_failure=None,
        commit_then_failure=None,
        rollback_failure=None,
        rollback_noop=False,
        close_failure=None,
        close_failures_remaining=None,
    ):
        self.connection = connection
        self.execute_failure = execute_failure
        self.execute_match = execute_match
        self.commit_failure = commit_failure
        self.commit_then_failure = commit_then_failure
        self.rollback_failure = rollback_failure
        self.rollback_noop = rollback_noop
        self.close_failure = close_failure
        self.close_failures_remaining = close_failures_remaining
        self.close_calls = 0

    def execute(self, sql, *args):
        if (
            self.execute_failure is not None
            and self.execute_match(sql)
        ):
            raise self.execute_failure
        return self.connection.execute(sql, *args)

    def commit(self):
        if self.commit_then_failure is not None:
            self.connection.commit()
            raise self.commit_then_failure
        if self.commit_failure is not None:
            raise self.commit_failure
        return self.connection.commit()

    def rollback(self):
        if self.rollback_failure is not None:
            raise self.rollback_failure
        if self.rollback_noop:
            return None
        return self.connection.rollback()

    def close(self):
        self.close_calls += 1
        if self.close_failure is not None:
            if self.close_failures_remaining is None:
                raise self.close_failure
            if self.close_failures_remaining > 0:
                self.close_failures_remaining -= 1
                raise self.close_failure
        return self.connection.close()

    def __getattr__(self, name):
        return getattr(self.connection, name)


def _sqlite_fault(name, *, extended_code=None):
    error = sqlite3.OperationalError(f"fault injection: {name}")
    error.sqlite_errorcode = (
        getattr(sqlite3, name) if extended_code is None else extended_code
    )
    error.sqlite_errorname = name
    return error


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
                store._connection.execute("BEGIN IMMEDIATE")
                store._migration_reservation_active = True
                start_writes = Barrier(2)
                writer_attempting = Event()

                def write_events():
                    with SQLiteStore(database) as writer:
                        start_writes.wait()
                        writer_attempting.set()
                        for index in range(100):
                            _record(writer, "concurrent_event", {"index": index})

                with ThreadPoolExecutor(max_workers=1) as pool:
                    writer = pool.submit(write_events)
                    start_writes.wait()
                    self.assertTrue(writer_attempting.wait(10))
                    self.assertFalse(writer.done())
                    backup_path = store._create_verified_backup(database, version=4)
                    backup = sqlite3.connect(backup_path)
                    try:
                        self.assertEqual(
                            backup.execute(
                                "SELECT COUNT(*) FROM system_events"
                            ).fetchone()[0],
                            1,
                        )
                    finally:
                        backup.close()
                    store._connection.commit()
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

    def test_verified_manifest_records_watermark_and_detects_file_change(self):
        with TemporaryDirectory() as directory:
            database = Path(directory) / "origin.sqlite3"
            with SQLiteStore.initialize(database) as store:
                _record(store, "manifest_event", {"n": 1})
                store._connection.execute("BEGIN IMMEDIATE")
                store._migration_reservation_active = True
                original = SQLiteStore._run_online_backup
                observed = []

                def inspect_connections(source, destination):
                    actual = []
                    for connection in (source, destination):
                        actual.append(
                            (
                                connection.execute("PRAGMA journal_mode").fetchone()[0],
                                connection.execute("PRAGMA synchronous").fetchone()[0],
                                connection.execute("PRAGMA wal_autocheckpoint").fetchone()[0],
                                connection.execute("PRAGMA busy_timeout").fetchone()[0],
                                connection.execute("PRAGMA foreign_keys").fetchone()[0],
                                connection.execute("PRAGMA recursive_triggers").fetchone()[0],
                            )
                        )
                    observed.extend(actual)
                    original(source, destination)

                with patch.object(
                    SQLiteStore,
                    "_run_online_backup",
                    staticmethod(inspect_connections),
                ):
                    backup_path = store._create_verified_backup(database, version=4)
                self.assertEqual(observed, [("wal", 2, 1000, 5000, 1, 1)] * 2)
                manifest = SQLiteStore._verify_backup_manifest(backup_path)
                self.assertEqual(manifest["status"], "VERIFIED")
                self.assertEqual(manifest["source_schema_version"], 4)
                self.assertEqual(manifest["event_count"], 1)
                self.assertEqual(manifest["highest_event_id"], 1)
                self.assertEqual(manifest["sqlite_sequence"], 1)
                self.assertEqual(manifest["journal_mode"], "wal")
                self.assertEqual(manifest["synchronous"], "FULL")
                self.assertEqual(
                    manifest["checksum_scope"],
                    "finalized-main-database-after-wal-truncate-and-close",
                )
                wal_path = Path(str(backup_path) + "-wal")
                self.assertTrue(
                    not wal_path.exists() or wal_path.stat().st_size == 0
                )
                store._connection.rollback()

            with backup_path.open("ab") as artifact:
                artifact.write(b"tamper")
            with self.assertRaisesRegex(StorageError, "checksum"):
                SQLiteStore._verify_backup_manifest(backup_path)

    def test_verified_manifest_rejects_committed_wal_content_after_verification(self):
        with TemporaryDirectory() as directory:
            database = Path(directory) / "origin.sqlite3"
            with SQLiteStore.initialize(database) as store:
                store._connection.execute("BEGIN IMMEDIATE")
                store._migration_reservation_active = True
                backup_path = store._create_verified_backup(database, version=4)
                store._connection.rollback()

            reader = sqlite3.connect(backup_path, isolation_level=None)
            writer = None
            try:
                reader.execute("BEGIN")
                reader.execute("SELECT COUNT(*) FROM system_events").fetchone()
                writer = sqlite3.connect(backup_path, isolation_level=None)
                writer.execute("PRAGMA journal_mode=WAL")
                writer.execute(
                    """INSERT INTO system_events
                       (event_type, occurred_at_utc, payload_json, idempotency_key)
                       VALUES (?, ?, ?, ?)""",
                    (
                        "post_verification_write",
                        "2026-01-01T00:00:00Z",
                        "{}",
                        "test:00000000-0000-0000-0000-000000000099",
                    ),
                )
                writer.commit()
                writer.close()
                writer = None
                wal_path = Path(str(backup_path) + "-wal")
                self.assertTrue(wal_path.exists())
                self.assertGreater(wal_path.stat().st_size, 32)
                with self.assertRaisesRegex(StorageError, "WAL sidecar"):
                    SQLiteStore._verify_backup_manifest(backup_path)
            finally:
                if writer is not None:
                    writer.close()
                if reader.in_transaction:
                    reader.execute("ROLLBACK")
                reader.close()

    def test_backup_manifest_rejects_unexpected_wal_and_shm_sidecars(self):
        with TemporaryDirectory() as directory:
            database = Path(directory) / "origin.sqlite3"
            with SQLiteStore.initialize(database) as store:
                store._connection.execute("BEGIN IMMEDIATE")
                store._migration_reservation_active = True
                backup_path = store._create_verified_backup(database, version=4)
                store._connection.rollback()

            wal_path = Path(str(backup_path) + "-wal")
            shm_path = Path(str(backup_path) + "-shm")
            wal_path.write_bytes(b"unexpected WAL content")
            with self.assertRaisesRegex(StorageError, "WAL sidecar"):
                SQLiteStore._verify_backup_manifest(backup_path)
            wal_path.unlink()

            shm_path.write_bytes(b"")
            with self.assertRaisesRegex(StorageError, "SHM sidecar"):
                SQLiteStore._verify_backup_manifest(backup_path)
            shm_path.unlink()

            self.assertEqual(
                SQLiteStore._verify_backup_manifest(backup_path)["status"],
                "VERIFIED",
            )

    def test_backup_artifact_replacement_before_manifest_publication_is_detected(self):
        with TemporaryDirectory() as directory:
            database = Path(directory) / "origin.sqlite3"
            with SQLiteStore.initialize(database) as store:
                store._connection.execute("BEGIN IMMEDIATE")
                store._migration_reservation_active = True
                original = SQLiteStore._publish_backup_manifest
                replaced = False

                def replace_before_verified(cls, path, manifest, *, exclusive=False):
                    nonlocal replaced
                    if manifest.get("status") == "VERIFIED" and not replaced:
                        artifact = next(
                            Path(directory).glob("origin.sqlite3.v4-backup-*.sqlite3")
                        )
                        replacement = artifact.with_name(artifact.name + ".replacement")
                        replacement.write_bytes(artifact.read_bytes())
                        changed = sqlite3.connect(replacement)
                        try:
                            changed.execute("PRAGMA application_id=12345")
                        finally:
                            changed.close()
                        replacement.replace(artifact)
                        replaced = True
                    return original(path, manifest, exclusive=exclusive)

                with patch.object(
                    SQLiteStore,
                    "_publish_backup_manifest",
                    classmethod(replace_before_verified),
                ):
                    with self.assertRaises(StorageError) as caught:
                        store._create_verified_backup(database, version=4)
                self.assertRegex(str(caught.exception.__cause__), "checksum")
                backup_path = next(
                    path for path in Path(directory).glob("*.sqlite3")
                    if path != database
                )
                manifest = json.loads(
                    SQLiteStore._backup_manifest_path(backup_path).read_text()
                )
                self.assertEqual(manifest["status"], "REJECTED")
                store._connection.rollback()

    def test_backup_source_must_match_store_migration_reservation(self):
        with TemporaryDirectory() as directory:
            root = Path(directory)
            database = root / "owned.sqlite3"
            other_database = root / "other.sqlite3"
            with SQLiteStore.initialize(database) as store, SQLiteStore.initialize(
                other_database
            ):
                store._connection.execute("BEGIN IMMEDIATE")
                store._migration_reservation_active = True
                with self.assertRaisesRegex(StorageError, "does not match"):
                    store._create_verified_backup(other_database, version=4)
                self.assertEqual(
                    list(root.glob("other.sqlite3.v4-backup-*.sqlite3")), []
                )
                self.assertEqual(
                    list(root.glob("other.sqlite3.v4-backup-*.manifest.json")), []
                )
                store._connection.rollback()

    def test_backup_manifest_rejects_missing_incomplete_and_malformed_states(self):
        with TemporaryDirectory() as directory:
            database = Path(directory) / "origin.sqlite3"
            with SQLiteStore.initialize(database) as store:
                store._connection.execute("BEGIN IMMEDIATE")
                store._migration_reservation_active = True
                backup_path = store._create_verified_backup(database, version=4)
                manifest_path = SQLiteStore._backup_manifest_path(backup_path)
                original = manifest_path.read_text(encoding="utf-8")
                for value in (
                    "{\"manifest_format_version\":1,\"status\":\"INCOMPLETE\"}",
                    "{invalid json",
                ):
                    with self.subTest(value=value):
                        manifest_path.write_text(value, encoding="utf-8")
                        with self.assertRaises(StorageError):
                            SQLiteStore._verify_backup_manifest(backup_path)
                invalid = json.loads(original)
                invalid["manifest_format_version"] = 999
                manifest_path.write_text(json.dumps(invalid), encoding="utf-8")
                with self.assertRaises(StorageError):
                    SQLiteStore._verify_backup_manifest(backup_path)
                manifest_path.unlink()
                with self.assertRaises(StorageError):
                    SQLiteStore._verify_backup_manifest(backup_path)
                manifest_path.write_text(original, encoding="utf-8")
                store._connection.rollback()

    def test_backup_failure_keeps_rejected_artifact_and_never_verifies_it(self):
        with TemporaryDirectory() as directory:
            database = Path(directory) / "origin.sqlite3"
            with SQLiteStore.initialize(database) as store:
                store._connection.execute("BEGIN IMMEDIATE")
                store._migration_reservation_active = True
                original = SQLiteStore._run_online_backup
                observed = {}

                def fail_after_incomplete(source, destination):
                    manifests = list(Path(directory).glob("*.manifest.json"))
                    self.assertEqual(len(manifests), 1)
                    observed.update(json.loads(manifests[0].read_text()))
                    raise sqlite3.OperationalError("injected backup failure")

                with patch.object(
                    SQLiteStore,
                    "_run_online_backup",
                    staticmethod(fail_after_incomplete),
                ):
                    with self.assertRaises(StorageError):
                        store._create_verified_backup(database, version=4)
                self.assertEqual(observed["status"], "INCOMPLETE")
                artifacts = list(Path(directory).glob("*.sqlite3"))
                self.assertEqual(len(artifacts), 2)
                backup_path = next(path for path in artifacts if path != database)
                manifest = json.loads(
                    SQLiteStore._backup_manifest_path(backup_path).read_text()
                )
                self.assertEqual(manifest["status"], "REJECTED")
                with self.assertRaises(StorageError):
                    SQLiteStore._verify_backup_manifest(backup_path)
                store._connection.rollback()

                store._connection.execute("BEGIN IMMEDIATE")
                store._migration_reservation_active = True
                with patch.object(
                    SQLiteStore,
                    "_compare_backup_rows",
                    side_effect=StorageError("injected exact-row mismatch"),
                ):
                    with self.assertRaises(StorageError):
                        store._create_verified_backup(database, version=4)
                rejected = [
                    path
                    for path in Path(directory).glob("*.sqlite3")
                    if path != database
                    and json.loads(
                        SQLiteStore._backup_manifest_path(path).read_text()
                    )["status"]
                    == "REJECTED"
                ]
                self.assertEqual(len(rejected), 2)
                store._connection.rollback()

    def test_exact_backup_row_comparison_detects_all_row_differences(self):
        columns = """CREATE TABLE system_events (
            event_id INTEGER PRIMARY KEY,
            event_type TEXT,
            occurred_at_utc TEXT,
            payload_json TEXT,
            idempotency_key TEXT
        )"""
        original = [
            (2, "first", "2026-01-01T00:00:00Z", "{\"a\":1}", "test:00000000-0000-0000-0000-000000000001"),
            (7, "second", "2026-01-02T00:00:00Z", "{\"b\":2}", "test:00000000-0000-0000-0000-000000000002"),
        ]
        variants = (
            original[:-1],
            original + [(9, "extra", "2026-01-03T00:00:00Z", "{}", "test:00000000-0000-0000-0000-000000000003")],
            [original[0], (7, "changed", *original[1][2:])],
            [(2, "first", "changed", *original[0][3:]), original[1]],
            [(2, "first", original[0][2], "{\"a\":9}", original[0][4]), original[1]],
            [(2, "first", *original[0][2:4], "test:00000000-0000-0000-0000-000000000009"), original[1]],
            [(3, *original[0][1:]), original[1]],
            [(7, *original[0][1:]), (2, *original[1][1:])],
        )
        for rows in variants:
            with self.subTest(rows=rows), sqlite3.connect(":memory:") as source, sqlite3.connect(":memory:") as backup:
                source.execute(columns)
                backup.execute(columns)
                source.executemany("INSERT INTO system_events VALUES (?, ?, ?, ?, ?)", original)
                backup.executemany("INSERT INTO system_events VALUES (?, ?, ?, ?, ?)", rows)
                with self.assertRaises(StorageError):
                    SQLiteStore._compare_backup_rows(source, backup, version=3)

        with sqlite3.connect(":memory:") as source, sqlite3.connect(":memory:") as backup:
            source.execute(columns)
            backup.execute(columns)
            source.executemany("INSERT INTO system_events VALUES (?, ?, ?, ?, ?)", original)
            backup.executemany("INSERT INTO system_events VALUES (?, ?, ?, ?, ?)", original)
            SQLiteStore._compare_backup_rows(source, backup, version=3)

    def test_verified_manifest_publication_failure_cannot_publish_verified_backup(self):
        with TemporaryDirectory() as directory:
            database = Path(directory) / "origin.sqlite3"
            with SQLiteStore.initialize(database) as store:
                store._connection.execute("BEGIN IMMEDIATE")
                store._migration_reservation_active = True
                original = SQLiteStore._publish_backup_manifest

                def fail_verified(cls, path, manifest, *, exclusive=False):
                    if manifest.get("status") == "VERIFIED":
                        raise OSError("injected manifest publication failure")
                    return original(path, manifest, exclusive=exclusive)

                with patch.object(
                    SQLiteStore,
                    "_publish_backup_manifest",
                    classmethod(fail_verified),
                ):
                    with self.assertRaises(StorageError):
                        store._create_verified_backup(database, version=4)
                backup = next(Path(directory).glob("origin.sqlite3.v4-backup-*.sqlite3"))
                manifest = json.loads(
                    SQLiteStore._backup_manifest_path(backup).read_text()
                )
                self.assertEqual(manifest["status"], "REJECTED")
                with self.assertRaises(StorageError):
                    SQLiteStore._verify_backup_manifest(backup)
                store._connection.rollback()

    def test_exact_backup_row_comparison_supports_v1_v2_and_event_id_gaps(self):
        rows = [
            (2, "first", "2026-01-01T00:00:00Z", "{}"),
            (7, "second", "2026-01-02T00:00:00Z", "{\"x\":1}"),
        ]
        for version in (1, 2):
            with self.subTest(version=version), sqlite3.connect(":memory:") as source, sqlite3.connect(":memory:") as backup:
                for connection in (source, backup):
                    connection.execute(
                        """CREATE TABLE system_events (
                           event_id INTEGER PRIMARY KEY, event_type TEXT,
                           occurred_at_utc TEXT, payload_json TEXT)"""
                    )
                    connection.executemany(
                        "INSERT INTO system_events VALUES (?, ?, ?, ?)", rows
                    )
                SQLiteStore._compare_backup_rows(source, backup, version=version)

    def test_exclusive_backup_creation_never_overwrites_existing_artifact(self):
        fixed = uuid4()
        with TemporaryDirectory() as directory:
            database = Path(directory) / "origin.sqlite3"
            with SQLiteStore.initialize(database) as store:
                store._connection.execute("BEGIN IMMEDIATE")
                store._migration_reservation_active = True
                backup_path = database.with_name(
                    f"{database.name}.v4-backup-{str(fixed).replace('-', '')}.sqlite3"
                )
                backup_path.write_bytes(b"pre-existing evidence")
                with patch("origin_trader.storage.sqlite_store.uuid4", return_value=fixed):
                    with self.assertRaises(StorageError):
                        store._create_verified_backup(database, version=4)
                self.assertEqual(backup_path.read_bytes(), b"pre-existing evidence")
                self.assertFalse(
                    SQLiteStore._backup_manifest_path(backup_path).exists()
                )
                store._connection.rollback()

    def test_migration_lock_timeout_fails_without_creating_backup(self):
        with TemporaryDirectory() as directory:
            database = Path(directory) / "legacy-v3.sqlite3"
            with SQLiteStore.initialize(database) as store:
                _record(store, "legacy")
                store._connection.execute("PRAGMA user_version=3")
            blocker = sqlite3.connect(database, isolation_level=None)
            try:
                blocker.execute("BEGIN IMMEDIATE")
                with self.assertRaises(StorageError):
                    SQLiteStore(database)
                self.assertEqual(
                    list(Path(directory).glob("legacy-v3.sqlite3.v3-backup-*.sqlite3")),
                    [],
                )
            finally:
                blocker.execute("ROLLBACK")
                blocker.close()
            with SQLiteStore(database) as migrated:
                self.assertEqual(
                    migrated._connection.execute("PRAGMA user_version").fetchone()[0],
                    SCHEMA_VERSION,
                )

    def test_writer_committing_in_wal_transition_window_is_in_backup(self):
        with TemporaryDirectory() as directory:
            database = Path(directory) / "legacy-v3.sqlite3"
            with SQLiteStore.initialize(database) as store:
                _record(store, "before_transition")
                store._connection.execute("PRAGMA user_version=3")
            setup = sqlite3.connect(database)
            try:
                setup.execute("PRAGMA journal_mode=DELETE")
            finally:
                setup.close()

            reservation_window = Event()
            resume_migration = Event()
            original_begin = SQLiteStore._schema_transaction

            def pause_before_reservation(connection):
                reservation_window.set()
                if not resume_migration.wait(10):
                    raise TimeoutError("migration reservation test timed out")
                original_begin(connection)

            def migrate_and_close():
                with SQLiteStore(database) as migrated:
                    return migrated.read_events()

            with patch.object(
                SQLiteStore,
                "_schema_transaction",
                staticmethod(pause_before_reservation),
            ), ThreadPoolExecutor(max_workers=1) as pool:
                migration = pool.submit(migrate_and_close)
                self.assertTrue(reservation_window.wait(10))
                writer = sqlite3.connect(database, isolation_level=None, timeout=5)
                try:
                    writer.execute("PRAGMA busy_timeout=5000")
                    writer.execute(
                        """INSERT INTO system_events
                           (event_type, occurred_at_utc, payload_json, idempotency_key)
                           VALUES (?, ?, ?, ?)""",
                        (
                            "window_event",
                            "2026-02-01T00:00:00Z",
                            "{}",
                            "test:00000000-0000-0000-0000-000000000099",
                        ),
                    )
                finally:
                    writer.close()
                resume_migration.set()
                self.assertEqual(
                    [event.event_type for event in migration.result(timeout=20)],
                    ["before_transition", "window_event"],
                )

            backups = list(Path(directory).glob("legacy-v3.sqlite3.v3-backup-*.sqlite3"))
            self.assertEqual(len(backups), 1)
            backup = sqlite3.connect(backups[0])
            try:
                rows = backup.execute(
                    "SELECT event_type FROM system_events ORDER BY event_id"
                ).fetchall()
                self.assertEqual([row[0] for row in rows], ["before_transition", "window_event"])
            finally:
                backup.close()
            manifest = SQLiteStore._verify_backup_manifest(backups[0])
            self.assertEqual(manifest["event_count"], 2)

    def test_two_migration_processes_create_one_verified_backup(self):
        with TemporaryDirectory() as directory:
            database = Path(directory) / "legacy-v3.sqlite3"
            ready_dir = Path(directory) / "start-barrier"
            ready_dir.mkdir()
            with SQLiteStore.initialize(database) as store:
                _record(store, "legacy")
                store._connection.execute("PRAGMA user_version=3")
            script = textwrap.dedent(
                """
                import json, pathlib, sys, time
                sys.path.insert(0, sys.argv[1])
                from origin_trader.storage.sqlite_store import SQLiteStore
                ready_dir = pathlib.Path(sys.argv[3])
                label = sys.argv[4]
                (ready_dir / (label + '.ready')).write_text('ready')
                deadline = time.monotonic() + 15
                while not (ready_dir / 'go').exists():
                    if time.monotonic() > deadline:
                        raise TimeoutError('migration process start barrier timed out')
                    time.sleep(0.01)
                with SQLiteStore(sys.argv[2]) as store:
                    print(json.dumps({
                        'version': store._connection.execute('PRAGMA user_version').fetchone()[0]
                    }))
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
                        str(ready_dir),
                        str(index),
                    ],
                    cwd=str(Path(__file__).resolve().parents[1]),
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    text=True,
                )
                for index in range(2)
            ]
            deadline = time.monotonic() + 15
            while len(list(ready_dir.glob("*.ready"))) < 2:
                if time.monotonic() > deadline:
                    for process in processes:
                        process.terminate()
                    self.fail("migration subprocess start barrier timed out")
                time.sleep(0.01)
            (ready_dir / "go").write_text("go")
            results = [process.communicate(timeout=25) for process in processes]
            self.assertEqual(
                [process.returncode for process in processes],
                [0, 0],
                [stderr for _, stderr in results],
            )
            self.assertEqual([json.loads(out)["version"] for out, _ in results], [4, 4])
            backups = list(Path(directory).glob("legacy-v3.sqlite3.v3-backup-*.sqlite3"))
            self.assertEqual(len(backups), 1)
            self.assertEqual(
                SQLiteStore._verify_backup_manifest(backups[0])["status"],
                "VERIFIED",
            )

    def test_subprocess_termination_during_online_backup_leaves_incomplete_artifact(self):
        with TemporaryDirectory() as directory:
            root = Path(directory)
            database = root / "origin.sqlite3"
            ready = root / "backup-started"
            with SQLiteStore.initialize(database) as store:
                for index in range(96):
                    _record(store, "large_event", {"blob": "x" * 16384, "i": index})

            script = textwrap.dedent(
                """
                import pathlib, sys, time
                sys.path.insert(0, sys.argv[1])
                from origin_trader.storage.sqlite_store import SQLiteStore
                ready = pathlib.Path(sys.argv[3])
                def slow_backup(source, destination):
                    def progress(status, remaining, total):
                        if not ready.exists():
                            ready.write_text('started')
                            time.sleep(60)
                    source.backup(destination, pages=1, progress=progress)
                SQLiteStore._run_online_backup = staticmethod(slow_backup)
                store = SQLiteStore(sys.argv[2])
                store._connection.execute('BEGIN IMMEDIATE')
                store._migration_reservation_active = True
                store._create_verified_backup(pathlib.Path(sys.argv[2]), version=4)
                """
            )
            process = subprocess.Popen(
                [sys.executable, "-c", script, self._source_path(), str(database), str(ready)],
                cwd=str(Path(__file__).resolve().parents[1]),
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
            )
            try:
                deadline = time.monotonic() + 20
                while not ready.exists() and time.monotonic() < deadline:
                    if process.poll() is not None:
                        break
                    time.sleep(0.02)
                self.assertTrue(ready.exists(), "child did not enter the backup API")
            finally:
                process.terminate()
                process.communicate(timeout=10)
            backups = list(root.glob("origin.sqlite3.v4-backup-*.sqlite3"))
            self.assertEqual(len(backups), 1)
            manifest_path = SQLiteStore._backup_manifest_path(backups[0])
            self.assertTrue(manifest_path.exists())
            self.assertEqual(
                json.loads(manifest_path.read_text())["status"], "INCOMPLETE"
            )

    def test_subprocess_termination_before_verified_manifest_keeps_incomplete_state(self):
        with TemporaryDirectory() as directory:
            database = Path(directory) / "origin.sqlite3"
            with SQLiteStore.initialize(database) as store:
                _record(store, "manifest_crash")
            script = textwrap.dedent(
                """
                import os, pathlib, sys
                sys.path.insert(0, sys.argv[1])
                from origin_trader.storage.sqlite_store import SQLiteStore
                original = SQLiteStore._publish_backup_manifest
                def stop_before_verified(cls, path, manifest, *, exclusive=False):
                    if manifest.get('status') == 'VERIFIED':
                        os._exit(42)
                    return original(path, manifest, exclusive=exclusive)
                SQLiteStore._publish_backup_manifest = classmethod(stop_before_verified)
                store = SQLiteStore(sys.argv[2])
                store._connection.execute('BEGIN IMMEDIATE')
                store._migration_reservation_active = True
                store._create_verified_backup(pathlib.Path(sys.argv[2]), version=4)
                """
            )
            result = subprocess.run(
                [sys.executable, "-c", script, self._source_path(), str(database)],
                cwd=str(Path(__file__).resolve().parents[1]),
                capture_output=True,
                text=True,
                timeout=20,
            )
            self.assertEqual(result.returncode, 42, result.stderr)
            backups = list(Path(directory).glob("origin.sqlite3.v4-backup-*.sqlite3"))
            self.assertEqual(len(backups), 1)
            manifest = json.loads(
                SQLiteStore._backup_manifest_path(backups[0]).read_text()
            )
            self.assertEqual(manifest["status"], "INCOMPLETE")

    def test_subprocess_termination_before_migration_commit_preserves_source_and_backup(self):
        with TemporaryDirectory() as directory:
            root = Path(directory)
            database = root / "legacy-v3.sqlite3"
            ready = root / "migration-ready-to-commit"
            with SQLiteStore.initialize(database) as store:
                _record(store, "legacy_before_crash", {"keep": True})
                store._connection.execute("PRAGMA user_version=3")
            script = textwrap.dedent(
                """
                import pathlib, sys, time
                sys.path.insert(0, sys.argv[1])
                from origin_trader.storage.sqlite_store import SQLiteStore
                ready = pathlib.Path(sys.argv[3])
                original = SQLiteStore._migrate_v3_to_v4
                def pause_after_ddl(self, backup_path):
                    original(self, backup_path)
                    ready.write_text('ready')
                    time.sleep(60)
                SQLiteStore._migrate_v3_to_v4 = pause_after_ddl
                SQLiteStore(sys.argv[2])
                """
            )
            process = subprocess.Popen(
                [sys.executable, "-c", script, self._source_path(), str(database), str(ready)],
                cwd=str(Path(__file__).resolve().parents[1]),
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
            )
            try:
                deadline = time.monotonic() + 20
                while not ready.exists() and time.monotonic() < deadline:
                    if process.poll() is not None:
                        break
                    time.sleep(0.02)
                self.assertTrue(ready.exists(), "child did not reach uncommitted migration")
            finally:
                process.terminate()
                process.communicate(timeout=10)

            connection = sqlite3.connect(database)
            try:
                self.assertEqual(connection.execute("PRAGMA user_version").fetchone()[0], 3)
                self.assertEqual(
                    connection.execute("SELECT event_type FROM system_events").fetchone()[0],
                    "legacy_before_crash",
                )
            finally:
                connection.close()
            backups = list(root.glob("legacy-v3.sqlite3.v3-backup-*.sqlite3"))
            self.assertEqual(len(backups), 1)
            self.assertEqual(
                SQLiteStore._verify_backup_manifest(backups[0])["status"],
                "VERIFIED",
            )

    def test_backup_verification_rejects_unexpected_journal_mode(self):
        with TemporaryDirectory() as directory:
            database = Path(directory) / "origin.sqlite3"
            with SQLiteStore.initialize(database) as store:
                store._connection.execute("BEGIN IMMEDIATE")
                store._migration_reservation_active = True
                original = SQLiteStore._configure_connection
                calls = 0

                def change_reopened_backup_mode(instance):
                    nonlocal calls
                    calls += 1
                    if calls == 3:
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
                self.assertEqual(backups, [])
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
            backups = list(
                Path(directory).glob("legacy-v3.sqlite3.v3-backup-*.sqlite3")
            )
            self.assertEqual(len(backups), 1)
            self.assertEqual(
                SQLiteStore._verify_backup_manifest(backups[0])["status"],
                "VERIFIED",
            )

    def test_v3_wal_policy_migration_preserves_history_and_backup(self):
        with TemporaryDirectory() as directory:
            database = Path(directory) / "legacy-v3.sqlite3"
            with SQLiteStore.initialize(database) as store:
                _record(store, "before_v4", {"preserve": True})
                store._connection.execute(
                    "UPDATE sqlite_sequence SET seq = 12 WHERE name = 'system_events'"
                )
                store._connection.execute("PRAGMA user_version=3")
            with SQLiteStore(database) as store:
                events = store.read_events()
                self.assertEqual(len(events), 1)
                self.assertEqual(events[0].event_type, "before_v4")
                self.assertIsNotNone(events[0].idempotency_key)
                self.assertEqual(store._connection.execute("PRAGMA user_version").fetchone()[0], 4)
            backups = list(Path(directory).glob("legacy-v3.sqlite3.v3-backup-*.sqlite3"))
            self.assertEqual(len(backups), 1)
            manifest = SQLiteStore._verify_backup_manifest(backups[0])
            self.assertEqual(manifest["source_schema_version"], 3)
            self.assertEqual(manifest["event_count"], 1)
            self.assertEqual(manifest["highest_event_id"], 1)
            self.assertEqual(manifest["sqlite_sequence"], 12)
            backup = sqlite3.connect(backups[0])
            try:
                self.assertEqual(backup.execute("PRAGMA user_version").fetchone()[0], 3)
                self.assertEqual(backup.execute("PRAGMA journal_mode").fetchone()[0], "wal")
                self.assertEqual(backup.execute("SELECT COUNT(*) FROM system_events").fetchone()[0], 1)
                self.assertEqual(
                    backup.execute(
                        "SELECT seq FROM sqlite_sequence WHERE name='system_events'"
                    ).fetchone()[0],
                    12,
                )
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
                with self.assertRaisesRegex(StorageError, "Database migration failed") as caught:
                    SQLiteStore(database)
                self.assertIn("injected stop", str(caught.exception.__cause__))

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

    def test_begin_busy_does_not_invalidate_connection(self):
        with SQLiteStore.initialize(":memory:") as store:
            store._connection = FaultInjectingConnection(
                store._connection,
                execute_failure=_sqlite_fault("SQLITE_BUSY"),
                execute_match=lambda sql: sql.strip().upper() == "BEGIN IMMEDIATE",
            )
            with self.assertRaisesRegex(StorageError, "SQLITE_BUSY"):
                _record(store, "busy_begin")
            self.assertEqual(store._state, "OPEN")
            store._connection.execute_failure = None
            self.assertEqual(_record(store, "after_busy"), 1)

    def test_rollback_failure_invalidates_and_records_both_errors(self):
        with SQLiteStore.initialize(":memory:") as store:
            store._connection.execute(
                """
                CREATE TRIGGER reject_rollback_test
                BEFORE INSERT ON system_events
                WHEN NEW.event_type = 'rollback_failure'
                BEGIN SELECT RAISE(ABORT, 'injected insert failure'); END
                """
            )
            connection = store._connection
            store._connection = FaultInjectingConnection(
                connection,
                rollback_failure=sqlite3.OperationalError("injected rollback failure"),
            )
            with self.assertRaises(StorageError) as raised:
                _record(store, "rollback_failure")
            self.assertEqual(store._state, "INVALID")
            self.assertIsInstance(raised.exception.__cause__, sqlite3.Error)
            self.assertTrue(store._cleanup_errors)
            self.assertTrue(
                any("transaction cleanup also failed" in note.lower()
                    for note in raised.exception.__notes__)
            )
            with self.assertRaisesRegex(StorageError, "invalid"):
                store.read_events()
            with self.assertRaisesRegex(StorageError, "invalid"):
                _record(store, "after_rollback_failure")

    def test_rollback_returning_with_active_transaction_invalidates_connection(self):
        with SQLiteStore.initialize(":memory:") as store:
            store._connection.execute(
                """
                CREATE TRIGGER reject_noop_rollback_test
                BEFORE INSERT ON system_events
                WHEN NEW.event_type = 'rollback_postcondition'
                BEGIN SELECT RAISE(ABORT, 'injected insert failure'); END
                """
            )
            connection = store._connection
            proxy = FaultInjectingConnection(connection, rollback_noop=True)
            store._connection = proxy

            with self.assertRaises(StorageError) as raised:
                _record(store, "rollback_postcondition")

            self.assertTrue(
                any(
                    "transaction remains active" in str(error)
                    for error in store._cleanup_errors
                )
            )
            self.assertEqual(store._state, "INVALID")
            self.assertIsInstance(raised.exception.__cause__, sqlite3.Error)
            with self.assertRaisesRegex(StorageError, "invalid"):
                store.read_events()
            with self.assertRaisesRegex(StorageError, "invalid"):
                _record(store, "after_noop_rollback")
            with self.assertRaises(sqlite3.ProgrammingError):
                connection.execute("SELECT 1")

    def test_fault_injected_serious_sqlite_write_errors_invalidate_connection(self):
        faults = (
            ("SQLITE_IOERR", sqlite3.SQLITE_IOERR),
            ("SQLITE_FULL", sqlite3.SQLITE_FULL),
            ("SQLITE_CORRUPT", sqlite3.SQLITE_CORRUPT),
            ("SQLITE_NOTADB", sqlite3.SQLITE_NOTADB),
            ("SQLITE_PROTOCOL", sqlite3.SQLITE_PROTOCOL),
            ("SQLITE_READONLY", sqlite3.SQLITE_READONLY),
            ("SQLITE_LOCKED", sqlite3.SQLITE_LOCKED),
            ("SQLITE_CANTOPEN", sqlite3.SQLITE_CANTOPEN),
            ("SQLITE_INTERNAL", sqlite3.SQLITE_INTERNAL),
            ("SQLITE_IOERR_READ", sqlite3.SQLITE_IOERR | (1 << 8)),
        )
        for name, code in faults:
            with self.subTest(name=name), SQLiteStore.initialize(":memory:") as store:
                connection = store._connection
                store._connection = FaultInjectingConnection(
                    connection,
                    execute_failure=_sqlite_fault(name, extended_code=code),
                    execute_match=lambda sql: "INSERT INTO SYSTEM_EVENTS" in sql.upper(),
                )
                with self.assertRaises(StorageError) as raised:
                    _record(store, "serious_write_error")
                self.assertEqual(store._state, "INVALID")
                self.assertIn(name, str(raised.exception))
                self.assertIn(str(code), str(raised.exception))
                with self.assertRaisesRegex(StorageError, "invalid"):
                    store.read_events()
                with self.assertRaisesRegex(StorageError, "invalid"):
                    _record(store, "after_serious_error")

    def test_commit_error_invalidates_connection_and_does_not_return_event_id(self):
        with SQLiteStore.initialize(":memory:") as store:
            connection = store._connection
            store._connection = FaultInjectingConnection(
                connection,
                commit_failure=_sqlite_fault("SQLITE_IOERR"),
            )
            with self.assertRaisesRegex(StorageError, "outcome is uncertain"):
                _record(store, "commit_failure")
            self.assertEqual(store._state, "INVALID")
            with self.assertRaisesRegex(StorageError, "invalid"):
                _record(store, "after_commit_failure")

    def test_commit_succeeds_then_raises_and_fresh_retry_is_idempotent(self):
        with TemporaryDirectory() as directory:
            database = Path(directory) / "ambiguous-commit.sqlite3"
            key = f"test:{uuid4()}"
            store = SQLiteStore.initialize(database)
            connection = store._connection
            store._connection = FaultInjectingConnection(
                connection,
                commit_then_failure=_sqlite_fault("SQLITE_IOERR"),
            )
            with self.assertRaisesRegex(StorageError, "outcome is uncertain"):
                store.record_event("ambiguous_commit", {"value": 1}, key)
            self.assertEqual(store._state, "INVALID")
            with self.assertRaisesRegex(StorageError, "invalid"):
                store.read_events()

            with SQLiteStore(database) as fresh_store:
                self.assertEqual(
                    fresh_store._connection.execute("PRAGMA journal_mode").fetchone()[0],
                    "wal",
                )
                self.assertEqual(
                    fresh_store._connection.execute("PRAGMA synchronous").fetchone()[0],
                    2,
                )
                self.assertEqual(
                    fresh_store._connection.execute("PRAGMA wal_autocheckpoint").fetchone()[0],
                    1000,
                )
                self.assertEqual(
                    fresh_store._connection.execute("PRAGMA user_version").fetchone()[0],
                    4,
                )
                self.assertEqual(
                    fresh_store._connection.execute("PRAGMA integrity_check").fetchone()[0],
                    "ok",
                )
                before_retry = fresh_store.read_events()
                self.assertEqual(len(before_retry), 1)
                committed_id = before_retry[0].event_id
                retried_id = fresh_store.record_event(
                    "ambiguous_commit", {"value": 1}, key
                )
                self.assertEqual(retried_id, committed_id)
                self.assertEqual(len(fresh_store.read_events()), 1)

    def test_fault_injected_serious_read_error_invalidates_connection(self):
        with SQLiteStore.initialize(":memory:") as store:
            connection = store._connection
            store._connection = FaultInjectingConnection(
                connection,
                execute_failure=_sqlite_fault("SQLITE_CORRUPT"),
                execute_match=lambda sql: "FROM SYSTEM_EVENTS" in sql.upper(),
            )
            with self.assertRaisesRegex(StorageError, "invalidated") as raised:
                store.read_events()
            self.assertIn("SQLITE_CORRUPT", str(raised.exception))
            self.assertEqual(store._state, "INVALID")
            with self.assertRaisesRegex(StorageError, "invalid"):
                _record(store, "after_read_error")

    def test_malformed_persisted_json_invalidates_without_skipping_event(self):
        with SQLiteStore.initialize(":memory:") as store:
            store._connection.execute(
                """
                INSERT INTO system_events (
                    event_type, occurred_at_utc, payload_json, idempotency_key
                ) VALUES (?, ?, ?, ?)
                """,
                (
                    "malformed_payload",
                    "2026-01-01T00:00:00Z",
                    "[]",
                    f"test:{uuid4()}",
                ),
            )
            with self.assertRaisesRegex(StorageError, "malformed"):
                store.read_events()
            self.assertEqual(store._state, "INVALID")
            with self.assertRaisesRegex(StorageError, "invalid"):
                store.read_events()

    def test_failed_close_can_be_retried_without_reopening_store(self):
        store = SQLiteStore.initialize(":memory:")
        connection = store._connection
        proxy = FaultInjectingConnection(
            connection,
            close_failure=OSError("injected close failure"),
            close_failures_remaining=1,
        )
        store._connection = proxy
        with self.assertRaisesRegex(StorageError, "close failed"):
            store.close()
        self.assertEqual(store._state, "CLOSED")
        self.assertIsInstance(store._cleanup_errors[0], OSError)
        self.assertEqual(proxy.close_calls, 1)
        with self.assertRaisesRegex(StorageError, "closed"):
            store.read_events()
        with self.assertRaisesRegex(StorageError, "closed"):
            _record(store, "after_close_failure")

        store.close()
        self.assertEqual(proxy.close_calls, 2)
        with self.assertRaises(sqlite3.ProgrammingError):
            connection.execute("SELECT 1")
        store.close()
        self.assertEqual(proxy.close_calls, 2)
        with self.assertRaisesRegex(StorageError, "closed"):
            store.read_events()

    def test_context_cleanup_failure_does_not_mask_body_exception(self):
        store = SQLiteStore.initialize(":memory:")
        connection = store._connection
        store._connection = FaultInjectingConnection(
            connection, close_failure=OSError("injected close failure")
        )
        with self.assertRaisesRegex(RuntimeError, "body failure") as raised:
            with store:
                raise RuntimeError("body failure")
        self.assertEqual(store._state, "CLOSED")
        self.assertTrue(
            any("context-manager cleanup also failed" in note
                for note in raised.exception.__notes__)
        )
        connection.close()

    def test_commit_failure_rolls_back_and_does_not_return_event_id(self):
        with TemporaryDirectory() as directory:
            database = Path(directory) / "commit-failure.sqlite3"
            store = SQLiteStore.initialize(database)

            def deny_commit(action, argument1, argument2, database_name, trigger):
                if action == sqlite3.SQLITE_TRANSACTION and argument1 == "COMMIT":
                    return sqlite3.SQLITE_DENY
                return sqlite3.SQLITE_OK

            store._connection.set_authorizer(deny_commit)
            with self.assertRaisesRegex(StorageError, "outcome is uncertain"):
                _record(store, "commit_failure")
            self.assertEqual(store._state, "INVALID")
            with self.assertRaisesRegex(StorageError, "invalid"):
                _record(store, "after_commit_failure")

            with SQLiteStore(database) as reopened:
                self.assertEqual(reopened.read_events(), [])
                self.assertEqual(_record(reopened, "after_reopen"), 1)

    def test_migration_commit_acknowledgement_failure_reports_uncertain_outcome(self):
        with TemporaryDirectory() as directory:
            database = Path(directory) / "legacy-v3.sqlite3"
            with SQLiteStore.initialize(database) as initial:
                _record(initial, "legacy_event")
                initial._connection.execute("PRAGMA user_version=3")
            connection = sqlite3.connect(database, isolation_level=None)
            try:
                connection.execute("PRAGMA journal_mode=DELETE")
            finally:
                connection.close()

            raw = SQLiteStore._connect_existing(database.resolve())
            raw.row_factory = sqlite3.Row
            injected = FaultInjectingConnection(
                raw,
                commit_then_failure=sqlite3.OperationalError(
                    "injected lost COMMIT acknowledgement"
                ),
            )
            store = SQLiteStore.__new__(SQLiteStore)
            store._connection = injected
            store._database_path = database.resolve()
            store._state = "OPEN"
            store._connection_close_succeeded = False
            store._cleanup_errors = []
            store._migration_reservation_active = False
            store._configure_connection()
            store._configure_durability(allow_transition=True)

            with self.assertRaisesRegex(
                StorageError,
                "COMMIT outcome is uncertain.*connection was invalidated.*"
                "Reopen and independently verify",
            ):
                store._initialize_schema()
            self.assertEqual(store._state, "INVALID")
            with self.assertRaisesRegex(StorageError, "invalid"):
                store.read_events()

            with SQLiteStore(database) as reopened:
                self.assertEqual(
                    reopened._connection.execute("PRAGMA user_version").fetchone()[0],
                    SCHEMA_VERSION,
                )
                self.assertEqual(
                    [event.event_type for event in reopened.read_events()],
                    ["legacy_event"],
                )

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
        self.assertEqual(store._state, "OPEN")
        self.assertEqual(_record(store, "while_open"), 1)
        store.close()
        self.assertEqual(store._state, "CLOSED")
        store.close()

        with self.assertRaises(StorageError):
            store.read_events()
        with self.assertRaises(StorageError):
            _record(store, "while_closed")

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
                connection.execute(
                    "UPDATE sqlite_sequence SET seq = 9 WHERE name = 'system_events'"
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
                self.assertEqual(
                    connection.execute(
                        "SELECT seq FROM sqlite_sequence WHERE name = 'system_events'"
                    ).fetchone()[0],
                    9,
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
            self.assertEqual(
                SQLiteStore._verify_backup_manifest(backups[0])["source_schema_version"],
                1,
            )
            self.assertEqual(
                SQLiteStore._verify_backup_manifest(backups[0])["sqlite_sequence"],
                9,
            )
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
            self.assertEqual(
                SQLiteStore._verify_backup_manifest(backups[0])["source_schema_version"],
                2,
            )
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
            self.assertEqual(
                SQLiteStore._verify_backup_manifest(backups[0])["status"],
                "VERIFIED",
            )
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
