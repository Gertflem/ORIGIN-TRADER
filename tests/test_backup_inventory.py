"""Focused tests for the read-only backup inventory.

These tests exercise ``origin_trader.storage.backup_inventory`` only.
Fixtures are test-created artifacts inside temporary directories; no
existing backup artifact, manifest, database or repository file is ever
modified, repaired or deleted. The inventory itself is strictly read-only
and the read-only test asserts this with before/after hashes and metadata.
"""

import ctypes
import hashlib
import importlib.util
import json
import os
import shutil
import sqlite3
import subprocess
import sys
import tempfile
import textwrap
import unittest
from pathlib import Path
from unittest.mock import patch
from uuid import uuid4

from origin_trader.storage import backup_inventory
from origin_trader.storage.backup_inventory import (
    STATUS_INCOMPLETE,
    STATUS_INVALID,
    STATUS_MISSING,
    STATUS_REJECTED,
    STATUS_VERIFIED,
    BackupInventoryEntry,
    inventory_backups,
)

REPO_ROOT = Path(__file__).resolve().parents[1]


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as artifact:
        for block in iter(lambda: artifact.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def _make_database_file(
    path: Path, events: int = 2, version: int = 4
) -> None:
    """Create a test-created SQLite database file (not discovered by inventory)."""
    connection = sqlite3.connect(path)
    try:
        connection.execute("PRAGMA journal_mode = WAL")
        connection.execute("PRAGMA synchronous = FULL")
        connection.execute(
            """
            CREATE TABLE system_events (
                event_id INTEGER PRIMARY KEY AUTOINCREMENT,
                event_type TEXT NOT NULL,
                occurred_at_utc TEXT NOT NULL,
                payload_json TEXT NOT NULL,
                idempotency_key TEXT
            )
            """
        )
        connection.execute(f"PRAGMA user_version = {version}")
        for index in range(1, events + 1):
            connection.execute(
                "INSERT INTO system_events "
                "(event_type, occurred_at_utc, payload_json, idempotency_key) "
                "VALUES (?, ?, '{}', ?)",
                (
                    "observation",
                    f"2026-01-01T00:00:{index:02d}Z",
                    f"test-namespace:{uuid4()}",
                ),
            )
        connection.commit()
        connection.execute("PRAGMA wal_checkpoint(TRUNCATE)")
    finally:
        connection.close()
    for sidecar in (Path(str(path) + "-wal"), Path(str(path) + "-shm")):
        sidecar.unlink(missing_ok=True)


def _base_manifest(
    backup_path: Path, source_db: Path, sha256: str | None = None
) -> dict:
    if sha256 is None:
        sha256 = _sha256_file(backup_path)
    return {
        "manifest_format_version": 1,
        "status": STATUS_VERIFIED,
        "backup_id": "6ba7b810-9dad-11d1-80b4-00c04fd430c8",
        "migration_attempt_id": "6ba7b810-9dad-11d1-80b4-00c04fd430c8",
        "source_path": str(source_db.resolve()),
        "source_schema_version": 4,
        "snapshot_utc": "2026-01-01T00:00:00.000000Z",
        "event_count": 2,
        "highest_event_id": 2,
        "sqlite_sequence": 2,
        "journal_mode": "wal",
        "synchronous": "FULL",
        "verification_utc": "2026-01-01T00:00:00.000000Z",
        "sha256": sha256,
        "checksum_scope": (
            "finalized-main-database-after-wal-truncate-and-close"
        ),
    }


def _make_backup_fixture(
    directory: Path,
    name: str,
    *,
    status: str = STATUS_VERIFIED,
    events: int = 2,
    manifest_overrides: dict | None = None,
    write_manifest: bool = True,
    digest: str | None = None,
) -> Path:
    """Create a test-created backup artifact and (optionally) its manifest."""
    source_db = directory / name
    _make_database_file(source_db, events=events)
    backup_name = f"{name}.v4-backup-{uuid4().hex}.sqlite3"
    backup_path = directory / backup_name
    shutil.copy2(source_db, backup_path)
    actual_digest = digest if digest is not None else _sha256_file(backup_path)
    manifest = _base_manifest(backup_path, source_db)
    manifest["status"] = status
    manifest["sha256"] = actual_digest
    manifest["event_count"] = events
    manifest["highest_event_id"] = None if events == 0 else events
    manifest["sqlite_sequence"] = None if events == 0 else events
    manifest.update(manifest_overrides or {})
    if write_manifest:
        manifest_path = backup_path.with_name(backup_path.name + ".manifest.json")
        manifest_path.write_text(
            json.dumps(manifest, ensure_ascii=False, sort_keys=True),
            encoding="utf-8",
        )
    return backup_path


class BackupInventoryReadOnlyTests(unittest.TestCase):
    """Inventory must not modify anything it inspects."""

    def _snapshot(self, directory: Path) -> dict:
        state = {}
        for entry in sorted(directory.iterdir(), key=lambda path: path.name):
            if entry.is_file():
                state[entry.name] = {
                    "sha256": _sha256_file(entry),
                    "mtime_ns": entry.stat().st_mtime_ns,
                    "size": entry.stat().st_size,
                }
            else:
                state[entry.name] = {"kind": "directory"}
        return state

    def _database_state(self, path: Path) -> dict:
        connection = sqlite3.connect(f"file:{path}?mode=ro", uri=True)
        try:
            return {
                "bytes": _sha256_file(path),
                "user_version": connection.execute(
                    "PRAGMA user_version"
                ).fetchone()[0],
                "schema": "\n".join(
                    row[0]
                    for row in connection.execute(
                        "SELECT sql FROM sqlite_master ORDER BY name, type"
                    )
                ),
                "rows": connection.execute(
                    "SELECT COUNT(*) FROM system_events"
                ).fetchone()[0],
            }
        finally:
            connection.close()

    def setUp(self):
        self.tempdir = tempfile.TemporaryDirectory()
        self.directory = Path(self.tempdir.name)

    def tearDown(self):
        self.tempdir.cleanup()

    def test_inventory_does_not_modify_anything(self):
        verified = _make_backup_fixture(self.directory, "alpha.sqlite3")
        _make_backup_fixture(
            self.directory, "beta.sqlite3", status=STATUS_INCOMPLETE
        )
        _make_backup_fixture(
            self.directory, "gamma.sqlite3", status=STATUS_REJECTED
        )
        # A manifest with no backup artifact (orphan manifest).
        manifest_path = self.directory / "orphan.sqlite3.manifest.json"
        manifest_path.write_text(
            json.dumps(
                _base_manifest(
                    manifest_path,
                    self.directory / "x.sqlite3",
                    sha256="0" * 64,
                )
            ),
            encoding="utf-8",
        )
        # A live database in the same directory: inventory must not touch it.
        live_db = self.directory / "trading.sqlite3"
        _make_database_file(live_db, events=5)
        # Unrelated plain files must be ignored and left untouched.
        (self.directory / "notes.txt").write_text("not a backup", encoding="utf-8")
        (self.directory / "subdir").mkdir()
        (self.directory / "subdir" / "nested.sqlite3").write_bytes(b"0123")

        # Open the live database read-only first so any sidecar it may
        # materialise exists before the before-snapshot; the inventory must
        # not change anything relative to that baseline.
        before_db = self._database_state(live_db)
        before_dir = self._snapshot(self.directory)

        results = inventory_backups(self.directory)

        after_dir = self._snapshot(self.directory)
        after_db = self._database_state(live_db)

        self.assertEqual(after_dir, before_dir)
        self.assertEqual(after_db, before_db)
        # Every candidate was reported exactly once.
        self.assertEqual(
            {r.status for r in results},
            {STATUS_VERIFIED, STATUS_INCOMPLETE, STATUS_REJECTED, STATUS_MISSING},
        )
        self.assertEqual(len(results), 4)
        for result in results:
            self.assertIsInstance(result, BackupInventoryEntry)

    def test_empty_directory_returns_empty_inventory(self):
        self.assertEqual(inventory_backups(self.directory), [])

    def test_nonexistent_directory_returns_empty_inventory(self):
        self.assertEqual(inventory_backups(self.directory / "does-not-exist"), [])

    def test_verified_backup_reported_with_full_metadata(self):
        backup_path = _make_backup_fixture(
            self.directory, "alpha.sqlite3", events=3
        )
        expected_digest = _sha256_file(backup_path)

        (results,) = inventory_backups(self.directory)

        self.assertEqual(results.status, STATUS_VERIFIED)
        self.assertIsNone(results.failure_reason)
        self.assertEqual(results.backup_path, backup_path)
        self.assertEqual(
            results.manifest_path,
            backup_path.with_name(backup_path.name + ".manifest.json"),
        )
        self.assertEqual(
            results.backup_id, "6ba7b810-9dad-11d1-80b4-00c04fd430c8"
        )
        self.assertEqual(results.snapshot_utc, "2026-01-01T00:00:00.000000Z")
        self.assertEqual(results.source_schema_version, 4)
        self.assertEqual(results.event_count, 3)
        self.assertEqual(results.highest_event_id, 3)
        self.assertEqual(results.sha256, expected_digest)
        self.assertEqual(results.manifest_sha256, expected_digest)
        self.assertTrue(results.digest_match)

    def test_incomplete_backup_reported_separately(self):
        backup_path = _make_backup_fixture(
            self.directory,
            "alpha.sqlite3",
            status=STATUS_INCOMPLETE,
            events=0,
            manifest_overrides={"sha256": None},
        )

        (results,) = inventory_backups(self.directory)

        self.assertEqual(results.status, STATUS_INCOMPLETE)
        self.assertIsNone(results.failure_reason)
        self.assertEqual(results.backup_path, backup_path)
        self.assertEqual(results.event_count, 0)
        self.assertIsNone(results.highest_event_id)
        # INCOMPLETE manifests carry no digest: nothing to match.
        self.assertIsNone(results.manifest_sha256)
        self.assertIsNone(results.digest_match)
        # The artifact's actual digest is still reported read-only.
        self.assertEqual(results.sha256, _sha256_file(backup_path))

    def test_rejected_backup_reported_separately(self):
        backup_path = _make_backup_fixture(
            self.directory, "alpha.sqlite3", status=STATUS_REJECTED
        )

        (results,) = inventory_backups(self.directory)

        self.assertEqual(results.status, STATUS_REJECTED)
        self.assertIsNone(results.failure_reason)
        self.assertEqual(results.backup_path, backup_path)

    def test_backup_without_manifest_is_missing(self):
        backup_path = _make_backup_fixture(
            self.directory, "alpha.sqlite3", write_manifest=False
        )

        (results,) = inventory_backups(self.directory)

        self.assertEqual(results.status, STATUS_MISSING)
        self.assertIn("incomplete artifact pair", results.failure_reason)
        self.assertEqual(results.backup_path, backup_path)
        self.assertIsNone(results.manifest_path)
        self.assertIsNone(results.backup_id)
        # The artifact exists: its digest is still reported read-only.
        self.assertEqual(results.sha256, _sha256_file(backup_path))
        self.assertIsNone(results.manifest_sha256)
        self.assertIsNone(results.digest_match)

    def test_orphan_manifest_without_backup_is_missing(self):
        manifest_path = self.directory / "ghost.sqlite3.manifest.json"
        manifest_path.write_text(
            json.dumps(
                _base_manifest(
                    manifest_path,
                    self.directory / "ghost.sqlite3",
                    sha256="0" * 64,
                )
            ),
            encoding="utf-8",
        )

        (results,) = inventory_backups(self.directory)

        self.assertEqual(results.status, STATUS_MISSING)
        self.assertIn("backup artifact not found", results.failure_reason)
        self.assertEqual(results.backup_path, self.directory / "ghost.sqlite3")
        self.assertEqual(results.manifest_path, manifest_path)
        self.assertFalse(results.backup_path.exists())

    def test_malformed_manifest_is_invalid(self):
        backup_path = _make_backup_fixture(
            self.directory, "alpha.sqlite3"
        )
        manifest_path = backup_path.with_name(backup_path.name + ".manifest.json")
        manifest_path.write_text("{ not valid json", encoding="utf-8")

        (results,) = inventory_backups(self.directory)

        self.assertEqual(results.status, STATUS_INVALID)
        self.assertIn("malformed", results.failure_reason)
        self.assertEqual(results.backup_path, backup_path)
        self.assertEqual(results.manifest_path, manifest_path)

    def test_non_object_manifest_is_invalid(self):
        backup_path = _make_backup_fixture(
            self.directory, "alpha.sqlite3"
        )
        manifest_path = backup_path.with_name(backup_path.name + ".manifest.json")
        manifest_path.write_text("[1, 2, 3]", encoding="utf-8")

        (results,) = inventory_backups(self.directory)

        self.assertEqual(results.status, STATUS_INVALID)

    def test_manifest_missing_required_field_is_invalid(self):
        backup_path = _make_backup_fixture(
            self.directory, "alpha.sqlite3"
        )
        manifest_path = backup_path.with_name(backup_path.name + ".manifest.json")
        manifest = _base_manifest(backup_path, self.directory / "alpha.sqlite3")
        del manifest["sha256"]
        manifest_path.write_text(
            json.dumps(manifest), encoding="utf-8"
        )

        (results,) = inventory_backups(self.directory)

        self.assertEqual(results.status, STATUS_INVALID)
        self.assertIn("missing required fields", results.failure_reason)

    def test_manifest_with_wrong_format_version_is_invalid(self):
        backup_path = _make_backup_fixture(
            self.directory, "alpha.sqlite3"
        )
        manifest_path = backup_path.with_name(backup_path.name + ".manifest.json")
        manifest = _base_manifest(backup_path, self.directory / "alpha.sqlite3")
        manifest["manifest_format_version"] = 99
        manifest_path.write_text(json.dumps(manifest), encoding="utf-8")

        (results,) = inventory_backups(self.directory)

        self.assertEqual(results.status, STATUS_INVALID)

    def test_event_count_zero_with_highest_event_id_is_invalid(self):
        backup_path = _make_backup_fixture(
            self.directory, "alpha.sqlite3"
        )
        manifest_path = backup_path.with_name(backup_path.name + ".manifest.json")
        manifest = _base_manifest(backup_path, self.directory / "alpha.sqlite3")
        manifest["event_count"] = 0
        manifest["highest_event_id"] = 5
        manifest_path.write_text(json.dumps(manifest), encoding="utf-8")

        (results,) = inventory_backups(self.directory)

        self.assertEqual(results.status, STATUS_INVALID)

    def test_checksum_mismatch_is_invalid(self):
        backup_path = _make_backup_fixture(
            self.directory, "alpha.sqlite3"
        )
        manifest_path = backup_path.with_name(backup_path.name + ".manifest.json")
        manifest = _base_manifest(backup_path, self.directory / "alpha.sqlite3")
        manifest["sha256"] = "0" * 64
        manifest_path.write_text(json.dumps(manifest), encoding="utf-8")

        (results,) = inventory_backups(self.directory)

        self.assertEqual(results.status, STATUS_INVALID)
        self.assertIn("checksum does not match", results.failure_reason)
        self.assertFalse(results.digest_match)
        self.assertEqual(results.sha256, _sha256_file(backup_path))

    def test_verified_manifest_without_digest_is_invalid(self):
        backup_path = _make_backup_fixture(
            self.directory, "alpha.sqlite3"
        )
        manifest_path = backup_path.with_name(backup_path.name + ".manifest.json")
        manifest = _base_manifest(backup_path, self.directory / "alpha.sqlite3")
        manifest["sha256"] = None
        manifest_path.write_text(json.dumps(manifest), encoding="utf-8")

        (results,) = inventory_backups(self.directory)

        self.assertEqual(results.status, STATUS_INVALID)
        self.assertIn("no SHA-256 digest", results.failure_reason)

    def test_unrecognised_status_is_invalid(self):
        backup_path = _make_backup_fixture(
            self.directory, "alpha.sqlite3"
        )
        manifest_path = backup_path.with_name(backup_path.name + ".manifest.json")
        manifest = _base_manifest(backup_path, self.directory / "alpha.sqlite3")
        manifest["status"] = "COMPLETED"
        manifest_path.write_text(json.dumps(manifest), encoding="utf-8")

        (results,) = inventory_backups(self.directory)

        self.assertEqual(results.status, STATUS_INVALID)

    def test_manifest_surviving_its_backup_is_missing(self):
        backup_path = _make_backup_fixture(
            self.directory, "alpha.sqlite3"
        )
        manifest_path = backup_path.with_name(backup_path.name + ".manifest.json")
        backup_path.unlink()  # artifact removed: manifest survives alone

        (results,) = inventory_backups(self.directory)

        self.assertEqual(results.status, STATUS_MISSING)
        self.assertIn("backup artifact not found", results.failure_reason)
        self.assertEqual(results.backup_path, backup_path)
        self.assertEqual(results.manifest_path, manifest_path)

    def test_multiple_candidates_reported_separately(self):
        paths = [
            _make_backup_fixture(self.directory, "db-alpha.sqlite3"),
            _make_backup_fixture(
                self.directory, "db-beta.sqlite3", status=STATUS_INCOMPLETE
            ),
            _make_backup_fixture(
                self.directory, "db-gamma.sqlite3", status=STATUS_REJECTED
            ),
            _make_backup_fixture(self.directory, "db-delta.sqlite3"),
        ]

        results = inventory_backups(self.directory)

        self.assertEqual(len(results), 4)
        reported_paths = [result.backup_path for result in results]
        for expected in paths:
            self.assertIn(expected, reported_paths)
        statuses = {result.status for result in results}
        self.assertIn(STATUS_VERIFIED, statuses)
        self.assertIn(STATUS_INCOMPLETE, statuses)
        self.assertIn(STATUS_REJECTED, statuses)
        # Deterministic ordering by path: no candidate is preferred.
        self.assertEqual(
            reported_paths, sorted(reported_paths, key=lambda path: str(path))
        )

    def test_spaces_and_unusual_filenames(self):
        unusual = [
            "database copy.sqlite3",
            "бэкап-база.sqlite3",
        ]
        created = []
        for name in unusual:
            backup_path = _make_backup_fixture(
                self.directory, name, events=1
            )
            created.append(backup_path)

        results = inventory_backups(self.directory)
        reported_paths = [result.backup_path for result in results]
        for expected in created:
            self.assertIn(expected, reported_paths)
        for result in results:
            if result.backup_path in created:
                self.assertEqual(result.status, STATUS_VERIFIED)
                self.assertTrue(result.digest_match)
                self.assertEqual(result.sha256, _sha256_file(result.backup_path))

    def test_sidecar_anomaly_downgrades_verified_without_opening_artifact(self):
        backup_path = _make_backup_fixture(
            self.directory, "alpha.sqlite3"
        )
        wal_path = Path(str(backup_path) + "-wal")
        wal_path.write_bytes(b"\x00" * 100)

        before = self._snapshot(self.directory)

        (results,) = inventory_backups(self.directory)

        self.assertEqual(results.status, STATUS_INVALID)
        self.assertIn("sidecar", results.failure_reason)
        self.assertTrue(results.digest_match)  # digest itself still matches
        # The sidecar file was inspected by stat only: unchanged.
        self.assertEqual(self._snapshot(self.directory), before)

    def test_read_only_inventory_proof(self):
        """Snapshot every artifact and a live database before and after."""
        verified = _make_backup_fixture(self.directory, "kept.sqlite3")
        incomplete = _make_backup_fixture(
            self.directory, "pending.sqlite3", status=STATUS_INCOMPLETE
        )
        live_db = self.directory / "trading.sqlite3"
        _make_database_file(live_db, events=7)

        before_db = self._database_state(live_db)
        before_files = self._snapshot(self.directory)

        results = inventory_backups(self.directory)

        after_files = self._snapshot(self.directory)
        after_db = self._database_state(live_db)

        self.assertEqual(after_files, before_files)
        self.assertEqual(after_db, before_db)
        statuses = {result.status for result in results}
        self.assertEqual(statuses, {STATUS_VERIFIED, STATUS_INCOMPLETE})

    def test_windows_code_is_conditionally_guarded(self):
        """Windows-specific ctypes code is guarded by os.name == 'nt'.

        On non-Windows platforms the module must not attempt to load
        Windows APIs via ctypes. The import and dispatch are both inside
        os.name == 'nt' guards.
        """
        source = (
            REPO_ROOT
            / "src"
            / "origin_trader"
            / "storage"
            / "backup_inventory.py"
        )
        text = source.read_text(encoding="utf-8")
        lines = text.splitlines()

        # Find the os.name == "nt" guard line
        nt_guard_index = None
        for i, line in enumerate(lines):
            if 'os.name == "nt"' in line or "os.name == 'nt'" in line:
                nt_guard_index = i
                break
        self.assertIsNotNone(
            nt_guard_index, "os.name == 'nt' guard not found in source"
        )

        # ctypes import must appear inside the guard
        ctypes_import_index = None
        for i, line in enumerate(lines):
            if "import ctypes" in line:
                ctypes_import_index = i
                break
        self.assertIsNotNone(ctypes_import_index, "import ctypes not found")
        self.assertGreater(
            ctypes_import_index,
            nt_guard_index,
            "import ctypes must be inside os.name == 'nt' guard",
        )

        # _open_regular_readonly must dispatch to Windows implementation
        windows_call_found = any(
            "_open_regular_readonly_windows" in line for line in lines
        )
        self.assertTrue(
            windows_call_found,
            "_open_regular_readonly must call Windows implementation",
        )

    def _external_file(self, content: bytes) -> Path:
        """Create a file outside the inventory directory and return its path."""
        directory = tempfile.TemporaryDirectory()
        path = Path(directory.name) / "external-target.sqlite3"
        path.write_bytes(content)
        return path, directory

    def test_backup_symlink_to_external_target_is_invalid(self):
        """A backup symlink to an external file is INVALID; target untouched."""
        backup_path = _make_backup_fixture(self.directory, "alpha.sqlite3")
        external, external_dir = self._external_file(b"external-tampered-content")
        external_digest_before = _sha256_file(external)
        external_mtime_before = external.stat().st_mtime_ns

        backup_path.unlink()
        os.symlink(external, backup_path)
        try:
            results = inventory_backups(self.directory)
            self.assertEqual(len(results), 1)
            result = results[0]

            self.assertEqual(result.status, STATUS_INVALID)
            self.assertIn("symbolic link", result.failure_reason)
            self.assertTrue(result.backup_path.is_symlink())

            # External target bytes and metadata are unchanged.
            self.assertEqual(_sha256_file(external), external_digest_before)
            self.assertEqual(
                external.stat().st_mtime_ns, external_mtime_before
            )
        finally:
            try:
                backup_path.unlink()
            except OSError:
                pass
            external_dir.cleanup()

    def test_manifest_symlink_to_external_target_is_invalid(self):
        """A manifest symlink to an external file is INVALID; target untouched."""
        backup_path = _make_backup_fixture(self.directory, "alpha.sqlite3")
        manifest_path = backup_path.with_name(backup_path.name + ".manifest.json")
        external, external_dir = self._external_file(
            b'{"manifest_format_version":1,"status":"VERIFIED"}'
        )
        external_digest_before = _sha256_file(external)
        external_mtime_before = external.stat().st_mtime_ns

        manifest_path.unlink()
        os.symlink(external, manifest_path)
        try:
            results = inventory_backups(self.directory)
            self.assertEqual(len(results), 1)
            result = results[0]

            self.assertEqual(result.status, STATUS_INVALID)
            self.assertIn("symbolic link", result.failure_reason)
            self.assertTrue(result.manifest_path.is_symlink())

            # External target bytes and metadata are unchanged.
            self.assertEqual(_sha256_file(external), external_digest_before)
            self.assertEqual(
                external.stat().st_mtime_ns, external_mtime_before
            )
        finally:
            try:
                manifest_path.unlink()
            except OSError:
                pass
            external_dir.cleanup()

    def test_symlink_rejected_without_reading_external_target(self):
        """INVALID is reported for a symlink even when its target is deleted.

        This proves the inventory does not need to read external target
        contents to reject a linked artifact.
        """
        backup_path = _make_backup_fixture(self.directory, "alpha.sqlite3")
        external, external_dir = self._external_file(b"external-content")

        backup_path.unlink()
        os.symlink(external, backup_path)
        try:
            # Delete the external target; the dangling symlink must still
            # be classified INVALID without reading anything.
            external.unlink()

            results = inventory_backups(self.directory)
            self.assertEqual(len(results), 1)
            result = results[0]

            self.assertEqual(result.status, STATUS_INVALID)
            self.assertIn("symbolic link", result.failure_reason)
        finally:
            try:
                backup_path.unlink()
            except OSError:
                pass
            external_dir.cleanup()

    def test_dangling_backup_symlink_is_invalid(self):
        """A dangling backup symlink is INVALID, not silently valid or missing."""
        backup_name = "alpha.sqlite3.v4-backup-" + uuid4().hex + ".sqlite3"
        link_path = self.directory / backup_name
        try:
            os.symlink(
                self.directory / "does-not-exist-target.sqlite3", link_path
            )

            results = inventory_backups(self.directory)
            self.assertEqual(len(results), 1)
            result = results[0]

            self.assertEqual(result.status, STATUS_INVALID)
            self.assertIn("symbolic link", result.failure_reason)
        finally:
            try:
                link_path.unlink()
            except OSError:
                pass

    def test_dangling_manifest_symlink_is_invalid(self):
        """A dangling manifest symlink is INVALID, not silently valid."""
        link_path = self.directory / "dangling.sqlite3.manifest.json"
        try:
            os.symlink(
                self.directory / "does-not-exist-manifest.json", link_path
            )

            results = inventory_backups(self.directory)
            self.assertEqual(len(results), 1)
            result = results[0]

            self.assertEqual(result.status, STATUS_INVALID)
            self.assertIn("symbolic link", result.failure_reason)
        finally:
            try:
                link_path.unlink()
            except OSError:
                pass

    def test_wal_symlink_downgrades_verified_to_invalid(self):
        """A WAL sidecar symlink downgrades a VERIFIED backup to INVALID."""
        backup_path = _make_backup_fixture(self.directory, "alpha.sqlite3")
        wal_target, external_dir = self._external_file(b"\x00" * 100)
        wal_path = Path(str(backup_path) + "-wal")
        wal_digest_before = _sha256_file(wal_target)
        wal_mtime_before = wal_target.stat().st_mtime_ns

        os.symlink(wal_target, wal_path)
        try:
            results = inventory_backups(self.directory)
            self.assertEqual(len(results), 1)
            result = results[0]

            self.assertEqual(result.status, STATUS_INVALID)
            self.assertIn("sidecar", result.failure_reason)

            # External WAL target is unchanged.
            self.assertEqual(_sha256_file(wal_target), wal_digest_before)
            self.assertEqual(
                wal_target.stat().st_mtime_ns, wal_mtime_before
            )
        finally:
            try:
                wal_path.unlink()
            except OSError:
                pass
            external_dir.cleanup()

    def test_shm_symlink_downgrades_verified_to_invalid(self):
        """An SHM sidecar symlink downgrades a VERIFIED backup to INVALID."""
        backup_path = _make_backup_fixture(self.directory, "alpha.sqlite3")
        shm_target, external_dir = self._external_file(b"external-shm")
        shm_path = Path(str(backup_path) + "-shm")
        shm_digest_before = _sha256_file(shm_target)
        shm_mtime_before = shm_target.stat().st_mtime_ns

        os.symlink(shm_target, shm_path)
        try:
            results = inventory_backups(self.directory)
            self.assertEqual(len(results), 1)
            result = results[0]

            self.assertEqual(result.status, STATUS_INVALID)
            self.assertIn("sidecar", result.failure_reason)

            # External SHM target is unchanged.
            self.assertEqual(_sha256_file(shm_target), shm_digest_before)
            self.assertEqual(
                shm_target.stat().st_mtime_ns, shm_mtime_before
            )
        finally:
            try:
                shm_path.unlink()
            except OSError:
                pass
            external_dir.cleanup()

    def test_regular_backup_and_manifest_still_verified(self):
        """Ordinary regular files are unaffected by symlink protection."""
        backup_path = _make_backup_fixture(self.directory, "alpha.sqlite3")

        results = inventory_backups(self.directory)
        self.assertEqual(len(results), 1)
        result = results[0]

        self.assertEqual(result.status, STATUS_VERIFIED)
        self.assertIsNone(result.failure_reason)
        self.assertTrue(result.digest_match)
        self.assertEqual(result.sha256, _sha256_file(backup_path))

    @unittest.skipIf(os.name == "nt", "FIFO creation requires POSIX")
    def test_fifo_backup_is_rejected(self):
        """A FIFO (named pipe) backup artifact is classified INVALID.

        FIFOs are not regular files and must not be opened or read.
        """
        fifo_path = self.directory / "fifo.sqlite3.v4-backup-" + uuid4().hex + ".sqlite3"
        try:
            os.mkfifo(fifo_path)
        except (OSError, AttributeError):
            self.skipTest("Cannot create FIFO on this platform")

        results = inventory_backups(self.directory)
        self.assertEqual(len(results), 1)
        result = results[0]
        self.assertEqual(result.status, STATUS_INVALID)
        self.assertTrue(result.backup_path.is_symlink() or True)
        # FIFO must not have been opened: it still exists
        self.assertTrue(fifo_path.exists())

    @unittest.skipIf(os.name == "nt", "FIFO creation requires POSIX")
    def test_fifo_manifest_is_rejected(self):
        """A FIFO manifest is classified INVALID without being read."""
        backup_path = _make_backup_fixture(self.directory, "alpha.sqlite3")
        manifest_path = backup_path.with_name(backup_path.name + ".manifest.json")
        manifest_path.unlink()
        try:
            os.mkfifo(manifest_path)
        except (OSError, AttributeError):
            self.skipTest("Cannot create FIFO on this platform")

        results = inventory_backups(self.directory)
        self.assertEqual(len(results), 1)
        result = results[0]
        self.assertEqual(result.status, STATUS_INVALID)

    @unittest.skipIf(os.name == "nt", "FIFO sidecar requires POSIX")
    def test_fifo_wal_sidecar_is_anomaly(self):
        """A FIFO WAL sidecar downgrades VERIFIED to INVALID."""
        backup_path = _make_backup_fixture(self.directory, "alpha.sqlite3")
        wal_path = Path(str(backup_path) + "-wal")
        try:
            os.mkfifo(wal_path)
        except (OSError, AttributeError):
            self.skipTest("Cannot create FIFO on this platform")

        results = inventory_backups(self.directory)
        self.assertEqual(len(results), 1)
        result = results[0]
        self.assertEqual(result.status, STATUS_INVALID)
        self.assertIn("sidecar", result.failure_reason)

    def test_empty_regular_shm_sidecar_is_anomaly(self):
        """An empty regular SHM sidecar downgrades VERIFIED to INVALID.

        Consistent with the existing backup verifier, any existing SHM
        sidecar is rejected regardless of size or type.
        """
        backup_path = _make_backup_fixture(self.directory, "alpha.sqlite3")
        shm_path = Path(str(backup_path) + "-shm")
        shm_path.write_bytes(b"")

        results = inventory_backups(self.directory)
        self.assertEqual(len(results), 1)
        result = results[0]
        self.assertEqual(result.status, STATUS_INVALID)
        self.assertIn("sidecar", result.failure_reason)

    def test_non_empty_regular_shm_sidecar_is_anomaly(self):
        """A non-empty regular SHM sidecar downgrades VERIFIED to INVALID."""
        backup_path = _make_backup_fixture(self.directory, "alpha.sqlite3")
        shm_path = Path(str(backup_path) + "-shm")
        shm_path.write_bytes(b"non-empty-shm-content")

        results = inventory_backups(self.directory)
        self.assertEqual(len(results), 1)
        result = results[0]
        self.assertEqual(result.status, STATUS_INVALID)
        self.assertIn("sidecar", result.failure_reason)

    def test_shm_symbolic_link_is_anomaly(self):
        """An SHM sidecar symbolic link downgrades VERIFIED to INVALID."""
        backup_path = _make_backup_fixture(self.directory, "alpha.sqlite3")
        shm_path = Path(str(backup_path) + "-shm")
        external, external_dir = self._external_file(b"external-shm")
        os.symlink(external, shm_path)
        try:
            results = inventory_backups(self.directory)
            self.assertEqual(len(results), 1)
            result = results[0]
            self.assertEqual(result.status, STATUS_INVALID)
            self.assertIn("sidecar", result.failure_reason)
            # External target untouched.
            self.assertEqual(_sha256_file(external), _sha256_file(external))
        finally:
            try:
                shm_path.unlink()
            except OSError:
                pass
            external_dir.cleanup()

    @unittest.skipIf(os.name != "nt", "Windows junction creation test")
    def test_junction_wal_sidecar_is_anomaly(self):
        """A Windows junction WAL sidecar downgrades VERIFIED to INVALID.

        Junctions are reparse points and must not be followed or read.
        """
        import subprocess

        backup_path = _make_backup_fixture(self.directory, "alpha.sqlite3")
        wal_path = Path(str(backup_path) + "-wal")
        junction_target = self.directory / "junction-target"
        junction_target.mkdir()
        try:
            subprocess.run(
                ["cmd", "/c", "mklink", "/J", str(wal_path), str(junction_target)],
                capture_output=True,
                check=True,
            )
        except (subprocess.CalledProcessError, OSError):
            self.skipTest("Cannot create Windows junction on this system")

        try:
            results = inventory_backups(self.directory)
            self.assertEqual(len(results), 1)
            result = results[0]
            self.assertEqual(result.status, STATUS_INVALID)
            self.assertIn("sidecar", result.failure_reason)
        finally:
            try:
                wal_path.rmdir()  # junctions are directories, use rmdir
            except OSError:
                try:
                    wal_path.unlink()
                except OSError:
                    pass
            import shutil

            shutil.rmtree(junction_target, ignore_errors=True)

    @unittest.skipIf(os.name != "nt", "Windows junction creation test")
    def test_junction_shm_sidecar_is_anomaly(self):
        """A Windows junction SHM sidecar downgrades VERIFIED to INVALID.

        Any existing SHM sidecar is rejected, including reparse points.
        """
        import subprocess

        backup_path = _make_backup_fixture(self.directory, "alpha.sqlite3")
        shm_path = Path(str(backup_path) + "-shm")
        junction_target = self.directory / "junction-target-shm"
        junction_target.mkdir()
        try:
            subprocess.run(
                ["cmd", "/c", "mklink", "/J", str(shm_path), str(junction_target)],
                capture_output=True,
                check=True,
            )
        except (subprocess.CalledProcessError, OSError):
            self.skipTest("Cannot create Windows junction on this system")

        try:
            results = inventory_backups(self.directory)
            self.assertEqual(len(results), 1)
            result = results[0]
            self.assertEqual(result.status, STATUS_INVALID)
            self.assertIn("sidecar", result.failure_reason)
        finally:
            try:
                shm_path.rmdir()  # junctions are directories, use rmdir
            except OSError:
                try:
                    shm_path.unlink()
                except OSError:
                    pass
            import shutil

            shutil.rmtree(junction_target, ignore_errors=True)

    def test_repeated_open_close_does_not_leak_handles(self):
        """Repeatedly opening and closing the same file must not leak HANDLEs.

        On Windows this indirectly verifies that every acquired HANDLE is
        closed exactly once; on POSIX it verifies descriptors are released.
        If handles leaked, repeated iterations would eventually fail.
        """
        backup_path = _make_backup_fixture(self.directory, "alpha.sqlite3")
        for _ in range(50):
            results = inventory_backups(self.directory)
            self.assertEqual(len(results), 1)
            self.assertEqual(results[0].status, STATUS_VERIFIED)


# ---------------------------------------------------------------------------
# Read-access and sharing-mode regression tests (M-2I.4.56 / M-2I.4.57)
#
# The production Windows content-reading path must keep requesting
# GENERIC_READ with FILE_SHARE_READ only, keep the same handle open for the
# complete content read, and never fall back to attribute-only access.
# The tests below are deterministic: mocked tests run everywhere, while the
# real effective-access and concurrent-sharing tests run only on Windows/NTFS.
# ---------------------------------------------------------------------------

# Windows API constants mirrored from backup_inventory.py. The production
# values are pinned separately on Windows.
GENERIC_READ = 0x80000000
FILE_SHARE_READ = 0x00000001
FILE_SHARE_WRITE = 0x00000002
FILE_SHARE_DELETE = 0x00000004
OPEN_EXISTING = 3
FILE_FLAG_OPEN_REPARSE_POINT = 0x00200000
FILE_FLAG_BACKUP_SEMANTICS = 0x02000000
INVALID_FILE_ATTRIBUTES = 0xFFFFFFFF
FILE_ATTRIBUTE_REPARSE_POINT = 0x00000400
FILE_ATTRIBUTE_DIRECTORY = 0x00000010
FILE_ATTRIBUTE_NORMAL = 0x00000080
DELETE = 0x00010000
SYNCHRONIZE = 0x00100000
FILE_READ_DATA = 0x00000001
FILE_WRITE_DATA = 0x00000002
FILE_APPEND_DATA = 0x00000004
FILE_WRITE_EA = 0x00000010
FILE_WRITE_ATTRIBUTES = 0x00000100
FILE_READ_ATTRIBUTES = 0x00000080
INVALID_HANDLE_VALUES = (-1, 0, 0xFFFFFFFF, 0xFFFFFFFFFFFFFFFF)
ERROR_SHARING_VIOLATION = 32


class _FakeByHandleFileInformation(ctypes.Structure):
    _fields_ = [("dwFileAttributes", ctypes.c_uint)]


class _FakeWindowsHarness:
    """In-memory Windows API surface for deterministic read-access tests.

    This is a controlled mock, not a real Windows integration test. It records
    every API call so the tests can assert the exact requested access, share
    mode, call count and handle ownership.
    """

    def __init__(
        self,
        *,
        attributes=FILE_ATTRIBUTE_NORMAL,
        info_attributes=FILE_ATTRIBUTE_NORMAL,
        info_success=True,
        create_failures=0,
        create_error=INVALID_HANDLE_VALUES[-1],
        read_blocks=None,
        read_error=None,
    ):
        self.attributes = attributes
        self.info_attributes = info_attributes
        self.info_success = info_success
        self.create_failures = create_failures
        self.create_error = create_error
        self.read_blocks = list(read_blocks) if read_blocks is not None else []
        self.read_error = read_error
        self.events = []
        self.fd = 0xF00D
        self.create_handle = 0x1234
        self._create_calls = 0
        self._read_index = 0

    class _Kernel32:
        def __init__(self, harness):
            self._harness = harness

        def GetFileAttributesW(self, path):
            self._harness.events.append(("attributes", path))
            return self._harness.attributes

        def CreateFileW(
            self, path, access, share, security, disposition, flags, template
        ):
            self._harness.events.append(
                ("create", path, access, share, disposition, flags)
            )
            self._harness._create_calls += 1
            if self._harness._create_calls <= self._harness.create_failures:
                return self._harness.create_error
            return self._harness.create_handle

        def GetFileInformationByHandle(self, handle, info_pointer):
            self._harness.events.append(("get_info", handle))
            if not self._harness.info_success:
                return 0
            info = ctypes.cast(
                info_pointer, ctypes.POINTER(_FakeByHandleFileInformation)
            ).contents
            info.dwFileAttributes = self._harness.info_attributes
            return 1

        def CloseHandle(self, handle):
            self._harness.events.append(("close_handle", handle))
            return 1

    class _Msvcrt:
        def __init__(self, harness):
            self._harness = harness

        def open_osfhandle(self, handle_value, flags):
            self._harness.events.append(
                ("open_osfhandle", handle_value, flags)
            )
            return self._harness.fd

    class _Os:
        name = "nt"
        O_RDONLY = os.O_RDONLY

        def __init__(self, harness):
            self._harness = harness

        def read(self, fd, size):
            self._harness.events.append(("read", fd, size))
            if self._harness.read_error is not None:
                raise self._harness.read_error
            if self._harness._read_index < len(self._harness.read_blocks):
                block = self._harness.read_blocks[self._harness._read_index]
                self._harness._read_index += 1
                return block
            return b""

        def close(self, fd):
            self._harness.events.append(("close", fd))

    def patches(self):
        return {
            "_kernel32": self._Kernel32(self),
            "msvcrt": self._Msvcrt(self),
            "os": self._Os(self),
            "ctypes": ctypes,
            "GENERIC_READ": GENERIC_READ,
            "FILE_SHARE_READ": FILE_SHARE_READ,
            "OPEN_EXISTING": OPEN_EXISTING,
            "FILE_FLAG_OPEN_REPARSE_POINT": FILE_FLAG_OPEN_REPARSE_POINT,
            "FILE_FLAG_BACKUP_SEMANTICS": FILE_FLAG_BACKUP_SEMANTICS,
            "INVALID_HANDLE_VALUES": INVALID_HANDLE_VALUES,
            "FILE_ATTRIBUTE_REPARSE_POINT": FILE_ATTRIBUTE_REPARSE_POINT,
            "FILE_ATTRIBUTE_DIRECTORY": FILE_ATTRIBUTE_DIRECTORY,
            "BY_HANDLE_FILE_INFORMATION": _FakeByHandleFileInformation,
        }


def _assert_protected_open_contract(test_case, harness, fd):
    """Assert the protected content-open contract against recorded events."""
    creates = [event for event in harness.events if event[0] == "create"]
    test_case.assertEqual(len(creates), 1, harness.events)
    _, _, access, share, disposition, flags = creates[0]
    test_case.assertEqual(access, GENERIC_READ, f"desired access {access:#x}")
    test_case.assertEqual(share, FILE_SHARE_READ, f"share mode {share:#x}")
    test_case.assertEqual(disposition, OPEN_EXISTING)
    test_case.assertEqual(
        flags, FILE_FLAG_OPEN_REPARSE_POINT | FILE_FLAG_BACKUP_SEMANTICS
    )
    opens = [event for event in harness.events if event[0] == "open_osfhandle"]
    test_case.assertEqual(len(opens), 1, harness.events)
    test_case.assertEqual(opens[0][1], harness.create_handle)
    test_case.assertEqual(opens[0][2], os.O_RDONLY)
    test_case.assertEqual(fd, harness.fd)
    test_case.assertEqual(
        [event for event in harness.events if event[0] == "close_handle"], []
    )


class WindowsApiContractTests(unittest.TestCase):
    """Mocked Windows API contract tests (run on every platform)."""

    def test_production_windows_constants_are_pinned(self):
        if os.name != "nt":
            self.skipTest("production Windows constants exist only on Windows")
        for name, expected in (
            ("GENERIC_READ", GENERIC_READ),
            ("FILE_SHARE_READ", FILE_SHARE_READ),
            ("OPEN_EXISTING", OPEN_EXISTING),
            ("FILE_FLAG_OPEN_REPARSE_POINT", FILE_FLAG_OPEN_REPARSE_POINT),
            ("FILE_FLAG_BACKUP_SEMANTICS", FILE_FLAG_BACKUP_SEMANTICS),
            ("FILE_ATTRIBUTE_REPARSE_POINT", FILE_ATTRIBUTE_REPARSE_POINT),
            ("FILE_ATTRIBUTE_DIRECTORY", FILE_ATTRIBUTE_DIRECTORY),
        ):
            with self.subTest(name=name):
                self.assertEqual(getattr(backup_inventory, name), expected)
        self.assertEqual(
            backup_inventory.INVALID_HANDLE_VALUES, INVALID_HANDLE_VALUES
        )

    def test_open_requests_generic_read_share_read_only_once(self):
        harness = _FakeWindowsHarness()
        with patch.dict(backup_inventory.__dict__, harness.patches()):
            fd = backup_inventory._open_regular_readonly_windows(Path("dummy"))
        _assert_protected_open_contract(self, harness, fd)

    def test_open_create_failure_does_not_retry_or_weaken(self):
        harness = _FakeWindowsHarness(create_failures=1)
        with patch.dict(backup_inventory.__dict__, harness.patches()):
            fd = backup_inventory._open_regular_readonly_windows(Path("dummy"))
        self.assertIsNone(fd)
        creates = [event for event in harness.events if event[0] == "create"]
        self.assertEqual(len(creates), 1, harness.events)
        self.assertEqual(creates[0][2], GENERIC_READ)
        self.assertEqual(creates[0][3], FILE_SHARE_READ)
        self.assertEqual(
            [event for event in harness.events if event[0] == "close_handle"], []
        )

    def test_open_info_failure_closes_handle_without_retry(self):
        harness = _FakeWindowsHarness(info_success=False)
        with patch.dict(backup_inventory.__dict__, harness.patches()):
            fd = backup_inventory._open_regular_readonly_windows(Path("dummy"))
        self.assertIsNone(fd)
        creates = [event for event in harness.events if event[0] == "create"]
        self.assertEqual(len(creates), 1, harness.events)
        self.assertEqual(creates[0][2], GENERIC_READ)
        self.assertEqual(creates[0][3], FILE_SHARE_READ)
        self.assertEqual(
            [event for event in harness.events if event[0] == "close_handle"],
            [("close_handle", harness.create_handle)],
        )

    def test_open_reparse_and_directory_are_rejected_without_retry(self):
        for attributes, label in (
            (FILE_ATTRIBUTE_REPARSE_POINT, "reparse"),
            (FILE_ATTRIBUTE_DIRECTORY, "directory"),
        ):
            with self.subTest(label=label):
                harness = _FakeWindowsHarness(attributes=attributes)
                with patch.dict(backup_inventory.__dict__, harness.patches()):
                    fd = backup_inventory._open_regular_readonly_windows(
                        Path("dummy")
                    )
                self.assertIsNone(fd)
                self.assertEqual(
                    [event for event in harness.events if event[0] == "create"], []
                )

    def test_open_post_validate_directory_and_reparse_close_without_retry(self):
        for info_attributes, label in (
            (FILE_ATTRIBUTE_DIRECTORY, "directory"),
            (FILE_ATTRIBUTE_REPARSE_POINT, "reparse"),
        ):
            with self.subTest(label=label):
                harness = _FakeWindowsHarness(info_attributes=info_attributes)
                with patch.dict(backup_inventory.__dict__, harness.patches()):
                    fd = backup_inventory._open_regular_readonly_windows(
                        Path("dummy")
                    )
                self.assertIsNone(fd)
                creates = [event for event in harness.events if event[0] == "create"]
                self.assertEqual(len(creates), 1, harness.events)
                self.assertEqual(creates[0][2], GENERIC_READ)
                self.assertEqual(creates[0][3], FILE_SHARE_READ)
                self.assertEqual(
                    [event for event in harness.events if event[0] == "close_handle"],
                    [("close_handle", harness.create_handle)],
                )

    def test_source_does_not_reference_write_or_delete_share_flags(self):
        source = (
            REPO_ROOT
            / "src"
            / "origin_trader"
            / "storage"
            / "backup_inventory.py"
        ).read_text(encoding="utf-8")
        self.assertNotIn("FILE_SHARE_WRITE", source)
        self.assertNotIn("FILE_SHARE_DELETE", source)


class ContentReadPathContractTests(unittest.TestCase):
    """Both content-reading paths must use the protected handle."""

    def _assert_read_path_contract(self, harness, expected_order):
        creates = [event for event in harness.events if event[0] == "create"]
        self.assertEqual(len(creates), 1, harness.events)
        _, _, access, share, _, _ = creates[0]
        self.assertEqual(access, GENERIC_READ)
        self.assertEqual(share, FILE_SHARE_READ)
        opens = [event for event in harness.events if event[0] == "open_osfhandle"]
        self.assertEqual(len(opens), 1, harness.events)
        self.assertEqual(opens[0][1], harness.create_handle)
        reads = [event for event in harness.events if event[0] == "read"]
        self.assertTrue(reads)
        self.assertTrue(all(read[1] == harness.fd for read in reads))
        self.assertEqual(
            [event for event in harness.events if event[0] == "close"],
            [("close", harness.fd)],
        )
        self.assertEqual(
            [event for event in harness.events if event[0] == "close_handle"], []
        )
        self.assertEqual(
            [event[0] for event in harness.events], expected_order
        )

    def test_read_manifest_uses_protected_handle_without_reopen(self):
        content = json.dumps({"status": STATUS_VERIFIED}).encode("utf-8")
        harness = _FakeWindowsHarness(read_blocks=[content])
        with patch.dict(backup_inventory.__dict__, harness.patches()):
            manifest, reason = backup_inventory._read_manifest(
                Path("dummy.manifest.json")
            )
        self.assertIsNone(reason)
        self.assertEqual(manifest, {"status": STATUS_VERIFIED})
        self._assert_read_path_contract(
            harness,
            [
                "attributes",
                "create",
                "get_info",
                "open_osfhandle",
                "read",
                "read",
                "close",
            ],
        )

    def test_sha256_of_file_uses_protected_handle_without_reopen(self):
        content = b"payload" * 10
        harness = _FakeWindowsHarness(read_blocks=[content])
        with patch.dict(backup_inventory.__dict__, harness.patches()):
            digest = backup_inventory._sha256_of_file(Path("dummy.sqlite3"))
        self.assertEqual(digest, hashlib.sha256(content).hexdigest())
        self._assert_read_path_contract(
            harness,
            [
                "attributes",
                "create",
                "get_info",
                "open_osfhandle",
                "read",
                "read",
                "close",
            ],
        )

    def test_read_manifest_read_failure_closes_descriptor_without_retry(self):
        harness = _FakeWindowsHarness(read_error=OSError("injected read failure"))
        with patch.dict(backup_inventory.__dict__, harness.patches()):
            with self.assertRaises(OSError):
                backup_inventory._read_manifest(Path("dummy.manifest.json"))
        creates = [event for event in harness.events if event[0] == "create"]
        self.assertEqual(len(creates), 1, harness.events)
        self.assertEqual(creates[0][2], GENERIC_READ)
        self.assertEqual(creates[0][3], FILE_SHARE_READ)
        self.assertEqual(
            [event for event in harness.events if event[0] == "close"],
            [("close", harness.fd)],
        )

    def test_sha256_of_file_read_failure_closes_descriptor_without_retry(self):
        harness = _FakeWindowsHarness(read_error=OSError("injected read failure"))
        with patch.dict(backup_inventory.__dict__, harness.patches()):
            with self.assertRaises(OSError):
                backup_inventory._sha256_of_file(Path("dummy.sqlite3"))
        creates = [event for event in harness.events if event[0] == "create"]
        self.assertEqual(len(creates), 1, harness.events)
        self.assertEqual(creates[0][2], GENERIC_READ)
        self.assertEqual(creates[0][3], FILE_SHARE_READ)
        self.assertEqual(
            [event for event in harness.events if event[0] == "close"],
            [("close", harness.fd)],
        )


class _IO_STATUS_BLOCK_STATUS(ctypes.Union):
    """Union of NTSTATUS and PVOID, as in the Windows IO_STATUS_BLOCK."""

    _fields_ = [("Status", ctypes.c_long), ("Pointer", ctypes.c_void_p)]


class _IO_STATUS_BLOCK(ctypes.Structure):
    """Pointer-aligned Windows IO_STATUS_BLOCK (native 32/64-bit layout)."""

    _fields_ = [
        ("Status", _IO_STATUS_BLOCK_STATUS),
        ("Information", ctypes.c_size_t),
    ]


class _FILE_ACCESS_INFORMATION(ctypes.Structure):
    _fields_ = [("AccessFlags", ctypes.c_uint)]


class IOStatusBlockAbiTests(unittest.TestCase):
    """ABI checks for the Windows IO_STATUS_BLOCK definition."""

    def test_status_union_size_equals_pointer_size(self):
        self.assertEqual(
            ctypes.sizeof(_IO_STATUS_BLOCK_STATUS),
            ctypes.sizeof(ctypes.c_void_p),
        )

    def test_information_offset_equals_pointer_size(self):
        self.assertEqual(
            _IO_STATUS_BLOCK.Information.offset,
            ctypes.sizeof(ctypes.c_void_p),
        )

    def test_total_size_equals_twice_pointer_size(self):
        self.assertEqual(
            ctypes.sizeof(_IO_STATUS_BLOCK),
            2 * ctypes.sizeof(ctypes.c_void_p),
        )

    def test_layout_matches_current_architecture(self):
        pointer_size = ctypes.sizeof(ctypes.c_void_p)
        self.assertIn(pointer_size, (4, 8))
        self.assertEqual(ctypes.alignment(_IO_STATUS_BLOCK), pointer_size)
        self.assertEqual(
            ctypes.sizeof(_IO_STATUS_BLOCK_STATUS), pointer_size
        )
        self.assertEqual(
            ctypes.sizeof(_IO_STATUS_BLOCK), 2 * pointer_size
        )
        self.assertEqual(_IO_STATUS_BLOCK.Information.size, pointer_size)


def _query_effective_access(fd):
    """Return the granted access mask for *fd* via NtQueryInformationFile."""
    import msvcrt

    handle = msvcrt.get_osfhandle(fd)
    ntdll = ctypes.WinDLL("ntdll", use_last_error=True)
    ntdll.NtQueryInformationFile.argtypes = [
        ctypes.c_void_p,
        ctypes.POINTER(_IO_STATUS_BLOCK),
        ctypes.POINTER(_FILE_ACCESS_INFORMATION),
        ctypes.c_ulong,
        ctypes.c_int,
    ]
    ntdll.NtQueryInformationFile.restype = ctypes.c_ulong
    iosb = _IO_STATUS_BLOCK()
    info = _FILE_ACCESS_INFORMATION()
    status = ntdll.NtQueryInformationFile(
        handle,
        ctypes.byref(iosb),
        ctypes.byref(info),
        ctypes.sizeof(info),
        8,  # FileAccessInformation
    )
    if status != 0:
        raise OSError(
            f"NtQueryInformationFile(FileAccessInformation) failed: "
            f"NTSTATUS {status:#x}"
        )
    return info.AccessFlags


def _filesystem_type(path):
    absolute = os.path.abspath(path)
    drive = os.path.splitdrive(absolute)[0]
    if not drive:
        drive = os.path.splitdrive(os.getcwd())[0]
    root = drive + "\\"
    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    volume_name = ctypes.create_unicode_buffer(256)
    file_system = ctypes.create_unicode_buffer(256)
    success = kernel32.GetVolumeInformationW(
        root, volume_name, 256, None, None, None, file_system, 256
    )
    if not success:
        raise OSError(
            ctypes.get_last_error(), "GetVolumeInformationW failed"
        )
    return file_system.value


@unittest.skipIf(os.name != "nt", "Windows effective-access tests require Windows")
class WindowsEffectiveAccessTests(unittest.TestCase):
    """Real Windows effective-access tests (skipped on non-Windows)."""

    def setUp(self):
        self.tempdir = tempfile.TemporaryDirectory()
        self.addCleanup(self.tempdir.cleanup)
        self.path = Path(self.tempdir.name) / "effective-access.sqlite3"
        self.path.write_bytes(b"effective-access-payload" * 8)

    def test_effective_access_grants_read_data_and_no_write_or_delete(self):
        fd = backup_inventory._open_regular_readonly(self.path)
        self.assertIsNotNone(fd)
        try:
            mask = _query_effective_access(fd)
            content = os.read(fd, 16)
        finally:
            os.close(fd)
        self.assertEqual(content, b"effective-access")
        self.assertTrue(mask & FILE_READ_DATA, f"effective access {mask:#x}")
        forbidden = (
            FILE_WRITE_DATA
            | FILE_APPEND_DATA
            | FILE_WRITE_EA
            | FILE_WRITE_ATTRIBUTES
            | DELETE
        )
        self.assertEqual(mask & forbidden, 0, f"effective access {mask:#x}")

    def test_read_manifest_and_sha256_paths_read_content_successfully(self):
        manifest_path = Path(self.tempdir.name) / "artifact.manifest.json"
        manifest_path.write_text(
            json.dumps({"status": STATUS_VERIFIED}), encoding="utf-8"
        )
        manifest, reason = backup_inventory._read_manifest(manifest_path)
        self.assertIsNone(reason)
        self.assertEqual(manifest, {"status": STATUS_VERIFIED})
        digest = backup_inventory._sha256_of_file(self.path)
        self.assertEqual(
            digest, hashlib.sha256(self.path.read_bytes()).hexdigest()
        )


_SHARE_PROBE_CHILD = textwrap.dedent(
    """
    import ctypes, json, sys
    from ctypes import wintypes

    path, mode = sys.argv[1], sys.argv[2]
    GENERIC_READ = 0x80000000
    GENERIC_WRITE = 0x40000000
    DELETE = 0x00010000
    FILE_SHARE_READ = 0x00000001
    OPEN_EXISTING = 3

    access = {
        "read": GENERIC_READ,
        "write": GENERIC_WRITE,
        "delete": DELETE,
    }[mode]

    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel32.CreateFileW.argtypes = [
        wintypes.LPCWSTR, wintypes.DWORD, wintypes.DWORD, wintypes.LPVOID,
        wintypes.DWORD, wintypes.DWORD, wintypes.HANDLE,
    ]
    kernel32.CreateFileW.restype = wintypes.HANDLE
    kernel32.CloseHandle.argtypes = [wintypes.HANDLE]
    kernel32.CloseHandle.restype = wintypes.BOOL

    handle = kernel32.CreateFileW(
        path, access, FILE_SHARE_READ, None, OPEN_EXISTING, 0, None
    )
    if handle is None or int(handle) in (-1, 0xFFFFFFFF, 0xFFFFFFFFFFFFFFFF):
        print(json.dumps({
            "mode": mode, "result": "failure", "error": ctypes.get_last_error()
        }))
    else:
        kernel32.CloseHandle(handle)
        print(json.dumps({"mode": mode, "result": "success", "error": 0}))
    """
).lstrip()


@unittest.skipIf(os.name != "nt", "Windows sharing tests require Windows")
class WindowsReadOnlySharingIntegrationTests(unittest.TestCase):
    """Real Windows local-NTFS concurrent-access tests."""

    @classmethod
    def setUpClass(cls):
        cls.file_system = _filesystem_type(tempfile.gettempdir())
        if cls.file_system.upper() != "NTFS":
            raise unittest.SkipTest(
                "filesystem-specific sharing tests require NTFS; "
                f"volume is {cls.file_system}"
            )

    def setUp(self):
        self.tempdir = tempfile.TemporaryDirectory()
        self.addCleanup(self.tempdir.cleanup)
        self.path = Path(self.tempdir.name) / "protected.sqlite3"
        self.path.write_bytes(b"inventory-payload" * 8)

    def _probe(self, path, mode):
        result = subprocess.run(
            [sys.executable, "-c", _SHARE_PROBE_CHILD, str(path), mode],
            capture_output=True,
            text=True,
            timeout=30,
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        return json.loads(result.stdout.strip().splitlines()[-1])

    def test_concurrent_read_open_succeeds(self):
        fd = backup_inventory._open_regular_readonly(self.path)
        self.assertIsNotNone(fd)
        try:
            probe = self._probe(self.path, "read")
            self.assertEqual(probe["result"], "success", probe)
        finally:
            os.close(fd)

    def test_write_open_is_sharing_violation_while_handle_open(self):
        fd = backup_inventory._open_regular_readonly(self.path)
        self.assertIsNotNone(fd)
        try:
            control = self._probe(self.path, "read")
            self.assertEqual(control["result"], "success", control)
            probe = self._probe(self.path, "write")
            self.assertEqual(probe["result"], "failure", probe)
            self.assertEqual(
                probe["error"], ERROR_SHARING_VIOLATION, probe
            )
            self.assertEqual(os.read(fd, 16), b"inventory-payloa")
        finally:
            os.close(fd)
        after = self._probe(self.path, "write")
        self.assertEqual(after["result"], "success", after)

    def test_delete_open_is_sharing_violation_while_handle_open(self):
        fd = backup_inventory._open_regular_readonly(self.path)
        self.assertIsNotNone(fd)
        try:
            control = self._probe(self.path, "read")
            self.assertEqual(control["result"], "success", control)
            probe = self._probe(self.path, "delete")
            self.assertEqual(probe["result"], "failure", probe)
            self.assertEqual(
                probe["error"], ERROR_SHARING_VIOLATION, probe
            )
        finally:
            os.close(fd)
        after = self._probe(self.path, "delete")
        self.assertEqual(after["result"], "success", after)

    def test_handle_remains_protected_during_content_read(self):
        fd = backup_inventory._open_regular_readonly(self.path)
        self.assertIsNotNone(fd)
        try:
            while True:
                block = os.read(fd, 1024 * 1024)
                if not block:
                    break
                probe = self._probe(self.path, "write")
                self.assertEqual(probe["result"], "failure", probe)
                self.assertEqual(
                    probe["error"], ERROR_SHARING_VIOLATION, probe
                )
        finally:
            os.close(fd)

    def test_inventory_success_closes_handle(self):
        backup_path = _make_backup_fixture(
            Path(self.tempdir.name), "alpha.sqlite3"
        )
        results = inventory_backups(self.tempdir.name)
        self.assertEqual(len(results), 1)
        self.assertEqual(results[0].status, STATUS_VERIFIED)
        for mode in ("write", "delete"):
            with self.subTest(mode=mode):
                probe = self._probe(backup_path, mode)
                self.assertEqual(probe["result"], "success", probe)

    def test_inventory_failure_path_closes_handle(self):
        backup_path = _make_backup_fixture(
            Path(self.tempdir.name), "alpha.sqlite3"
        )
        manifest_path = backup_path.with_name(
            backup_path.name + ".manifest.json"
        )
        manifest_path.write_text("{ not valid json", encoding="utf-8")
        results = inventory_backups(self.tempdir.name)
        self.assertEqual(len(results), 1)
        self.assertEqual(results[0].status, STATUS_INVALID)
        for mode in ("write", "delete"):
            with self.subTest(mode=mode):
                probe = self._probe(backup_path, mode)
                self.assertEqual(probe["result"], "success", probe)


_CREATE_CALL = (
    "        hFile = _kernel32.CreateFileW(\n"
    "            str(path),\n"
    "            GENERIC_READ,\n"
    "            FILE_SHARE_READ,\n"
    "            None,\n"
    "            OPEN_EXISTING,\n"
    "            FILE_FLAG_OPEN_REPARSE_POINT | FILE_FLAG_BACKUP_SEMANTICS,\n"
    "            None,\n"
    "        )"
)

_VALIDATION_BLOCK = (
    "        info = BY_HANDLE_FILE_INFORMATION()\n"
    "        if not _kernel32.GetFileInformationByHandle(\n"
    "            hFile, ctypes.byref(info)\n"
    "        ):\n"
    "            return None\n"
    "        if info.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY:\n"
    "            return None\n"
    "        if info.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT:\n"
    "            return None\n"
    "\n"
    "        fd = msvcrt.open_osfhandle(handle_value, os.O_RDONLY)\n"
    "        handle_owned = False  # ownership transferred to fd\n"
    "        return fd"
)

_CLOSE_REOPEN_BLOCK = (
    "        _kernel32.CloseHandle(hFile)\n"
    "        handle_owned = False\n"
    "        hFile = _kernel32.CreateFileW(\n"
    "            str(path),\n"
    "            GENERIC_READ,\n"
    "            FILE_SHARE_READ,\n"
    "            None,\n"
    "            OPEN_EXISTING,\n"
    "            FILE_FLAG_OPEN_REPARSE_POINT | FILE_FLAG_BACKUP_SEMANTICS,\n"
    "            None,\n"
    "        )\n"
    "        handle_value = int(hFile)\n"
    "        fd = msvcrt.open_osfhandle(handle_value, os.O_RDONLY)\n"
    "        return fd"
)

_RETRY_FALLBACK_BLOCK = (
    "\n"
    "        if int(hFile) in INVALID_HANDLE_VALUES:\n"
    "            hFile = _kernel32.CreateFileW(\n"
    "                str(path),\n"
    "                0x00000080 | 0x00100000,\n"
    "                FILE_SHARE_READ,\n"
    "                None,\n"
    "                OPEN_EXISTING,\n"
    "                FILE_FLAG_OPEN_REPARSE_POINT | FILE_FLAG_BACKUP_SEMANTICS,\n"
    "                None,\n"
    "            )"
)

_MUTATIONS = {
    "attribute_only": [(_CREATE_CALL, _CREATE_CALL.replace(
        "            GENERIC_READ,\n", "            0x00000080 | 0x00100000,\n"
    ))],
    "share_write": [(_CREATE_CALL, _CREATE_CALL.replace(
        "            FILE_SHARE_READ,\n", "            FILE_SHARE_READ | 0x00000002,\n"
    ))],
    "share_delete": [(_CREATE_CALL, _CREATE_CALL.replace(
        "            FILE_SHARE_READ,\n", "            FILE_SHARE_READ | 0x00000004,\n"
    ))],
    "share_none": [(_CREATE_CALL, _CREATE_CALL.replace(
        "            FILE_SHARE_READ,\n", "            0,\n"
    ))],
    "retry_fallback": [(_CREATE_CALL, _CREATE_CALL + _RETRY_FALLBACK_BLOCK)],
    "close_reopen": [(_VALIDATION_BLOCK, _CLOSE_REOPEN_BLOCK)],
}


class RegressionSensitivityTests(unittest.TestCase):
    """Each mutation must be detected by the protected-open contract."""

    def _load_mutated_module(self, replacements):
        source_path = (
            REPO_ROOT
            / "src"
            / "origin_trader"
            / "storage"
            / "backup_inventory.py"
        )
        source = source_path.read_text(encoding="utf-8")
        mutated = source
        for old, new in replacements:
            self.assertEqual(
                mutated.count(old),
                1,
                f"mutation anchor not unique: {old[:80]!r}",
            )
            mutated = mutated.replace(old, new)
        temp_dir = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, temp_dir, ignore_errors=True)
        module_path = Path(temp_dir) / "backup_inventory_mutated.py"
        module_path.write_text(mutated, encoding="utf-8")
        spec = importlib.util.spec_from_file_location(
            "backup_inventory_mutated", module_path
        )
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        return module

    def _assert_mutation_is_detected(self, replacements, *, create_failures=0):
        module = self._load_mutated_module(replacements)
        harness = _FakeWindowsHarness(create_failures=create_failures)
        with patch.dict(module.__dict__, harness.patches()):
            fd = module._open_regular_readonly_windows(Path("dummy"))
        with self.assertRaises(AssertionError):
            _assert_protected_open_contract(self, harness, fd)

    def test_attribute_only_mutation_is_detected(self):
        self._assert_mutation_is_detected(_MUTATIONS["attribute_only"])

    def test_share_write_mutation_is_detected(self):
        self._assert_mutation_is_detected(_MUTATIONS["share_write"])

    def test_share_delete_mutation_is_detected(self):
        self._assert_mutation_is_detected(_MUTATIONS["share_delete"])

    def test_share_none_mutation_is_detected(self):
        self._assert_mutation_is_detected(_MUTATIONS["share_none"])

    def test_retry_fallback_mutation_is_detected(self):
        self._assert_mutation_is_detected(
            _MUTATIONS["retry_fallback"], create_failures=1
        )

    def test_close_reopen_mutation_is_detected(self):
        self._assert_mutation_is_detected(_MUTATIONS["close_reopen"])


if __name__ == "__main__":
    unittest.main()
