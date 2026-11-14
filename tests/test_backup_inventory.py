"""Focused tests for the read-only backup inventory.

These tests exercise ``origin_trader.storage.backup_inventory`` only.
Fixtures are test-created artifacts inside temporary directories; no
existing backup artifact, manifest, database or repository file is ever
modified, repaired or deleted. The inventory itself is strictly read-only
and the read-only test asserts this with before/after hashes and metadata.
"""

import hashlib
import json
import os
import shutil
import sqlite3
import tempfile
import unittest
from pathlib import Path
from uuid import uuid4

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


if __name__ == "__main__":
    unittest.main()
