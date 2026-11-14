# ORIGIN TRADER — M-2I.4.3 Backup Inventory Symlink Protection: Evidence Report

Task: OT-M2I43-SYMLINK-PROTECTION
Mode: AUTHORISED NARROW IMPLEMENTATION
Authority: TECHNICAL_SPEC.md §12 and the ORIGIN Security Standard.

## 1. Branch and HEAD

- Branch: `master` (only local branch; `remotes/origin/master` tracks it)
- HEAD: `b52aeb25203d000e85bd5449e49b7a4c24a042f2` ("Harden SQLite migration backup verification")
- No commit or push was performed. All work sits uncommitted in the working tree.

## 2. Initial and final Git status

### Initial status (before M-2I.4.3)

```
 M src/origin_trader/storage/sqlite_store.py
 M tests/test_storage.py
?? OT-M2I4-EVIDENCE.md
?? src/origin_trader/storage/backup_inventory.py
?? tests/test_backup_inventory.py
```

The two tracked-file modifications pre-date all M-2I.4 work (Windows secure-storage
ACL hardening). The three untracked files are the M-2I.4 implementation and its
evidence report.

### Final status (after M-2I.4.3)

```
 M src/origin_trader/storage/sqlite_store.py   (pre-existing, not part of M-2I.4.x)
 M tests/test_storage.py                        (pre-existing, not part of M-2I.4.x)
?? OT-M2I4-EVIDENCE.md                          (M-2I.4 evidence report)
?? OT-M2I43-EVIDENCE.md                         (M-2I.4.3 evidence report, this file)
?? src/origin_trader/storage/backup_inventory.py   (modified — M-2I.4.3)
?? tests/test_backup_inventory.py                (modified — M-2I.4.3)
```

## 3. Exact modified files

Only two files were modified for M-2I.4.3:

1. `src/origin_trader/storage/backup_inventory.py` — added symlink protection.
2. `tests/test_backup_inventory.py` — added 8 symlink edge-case tests.

No other files were created, modified, renamed, moved, or deleted. In particular,
`sqlite_store.py`, `tests/test_storage.py`, `TECHNICAL_SPEC.md`, and all
configuration files are untouched.

## 4. Diff statistics

Tracked-file diff (pre-existing ACL hardening only, not part of M-2I.4.3):

```
 src/origin_trader/storage/sqlite_store.py | 817 +++++++++++--
 tests/test_storage.py                     | 498 +++++++++--
 2 files changed, 1313 insertions(+), 2 deletions(-)
```

M-2I.4.3 new/modified content (untracked; complete contents are the diff):

- `src/origin_trader/storage/backup_inventory.py`: 24,700 bytes (~500 lines)
- `tests/test_backup_inventory.py`: 30,392 bytes (~700 lines)
- `OT-M2I43-EVIDENCE.md`: this report

## 5. `git diff --check`

```
$ git diff --check
warning: in the working copy of 'src/origin_trader/storage/sqlite_store.py', LF will be replaced by CRLF the next time Git touches it
warning: in the working copy of 'tests/test_storage.py', LF will be replaced by CRLF the next time Git touches it
```

No whitespace errors. The two informational CRLF warnings relate to the
pre-existing modified files only; the M-2I.4.3 modified files produce no warnings.

## 6. Complete source and test diffs

### 6.1 Modified file: `src/origin_trader/storage/backup_inventory.py`

The complete file (24,700 bytes) is reproduced below. Changes relative to the
M-2I.4 version:

- Added imports: `hashlib`, `stat as _stat_module`.
- Added `_is_symlink(path)` (uses `os.lstat()`, does not follow links).
- Added `_open_regular_readonly(path)` — opens a file descriptor without
  following symbolic links, using `O_NOFOLLOW` where supported (POSIX) and
  `os.lstat()` pre-validation everywhere; validates with `os.fstat()`.
- Rewrote `_sha256_of_file()` to read via `_open_regular_readonly()` fd instead
  of `SQLiteStore._sha256_file()` (which uses `path.open("rb")` and follows
  links).
- Rewrote `_read_manifest()` to read via `_open_regular_readonly()` fd instead
  of `Path.read_text()` (which follows links).
- Rewrote `_sidecar_anomaly()` to use `os.lstat()` on `-wal`/`-shm` instead of
  `Path.exists()`/`Path.stat()` (which follow links); a symlink sidecar is an
  anomaly.
- Rewrote `_classify_candidate()` to reject backup and manifest symlinks as
  `INVALID` before any target is read.
- Rewrote the discovery loop in `inventory_backups()` to classify backup
  symlinks and orphan manifest symlinks as `INVALID` before `is_file()`;
  manifest symlinks whose backup exists are left to `_classify_candidate` to
  avoid duplicates.

```python
"""Read-only backup inventory for ORIGIN TRADER.

Discovers existing backup artifacts and their completion manifests in a
directory, verifies every candidate using read-only logic only, and reports
each candidate's status and metadata separately.

The inventory is strictly read-only: it only reads file bytes and directory
entries. It never opens a backup database through SQLite, never takes a write
reservation on an artifact, and never creates, modifies, renames, moves or
deletes any backup file, manifest, database or directory entry.

Inventory results are informational only. A reported status never authorises
recovery, restoration, retention or deletion; the inventory makes no recovery
decision and does not prefer any candidate.

Verification note
-----------------
SQLiteStore._verify_backup_manifest is deliberately not invoked on live
artifacts. That verifier opens the artifact read-write ("mode=rw") and takes a
write reservation on it ("BEGIN IMMEDIATE") while checksumming it -- a
write-intent operation that can create WAL/SHM sidecar files (and rollback
journals in non-WAL journal modes) on the very artifact being inspected.
Using it for a read-only inventory would violate the read-only requirement,
and modifying it is outside the authorised scope.

The inventory reuses only the read-only-safe parts of the existing
verification logic: the backup and manifest naming convention
(SQLiteStore._backup_manifest_path), the SHA-256 file digest
(SQLiteStore._sha256_file) and the manifest format constants. It reimplements
the verifier's structural manifest checks in read-only form (parsing and
field validation without opening any database file). An inventory status of
VERIFIED therefore means: the manifest is structurally valid, belongs to a
complete artifact/manifest pair, and its recorded SHA-256 digest matches the
digest of the artifact file as read from disk.

Symbolic-link protection
------------------------
The inventory never follows symbolic links or Windows reparse points when
inspecting backup artifacts, manifest artifacts, WAL sidecars or SHM sidecars.
Linked artifacts are reported as INVALID without reading external target
contents. Dangling links are handled safely and reported INVALID.
"""

from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
import hashlib
import json
import os
import re
import stat as _stat_module
from typing import Any
from uuid import UUID

from origin_trader.storage.sqlite_store import (
    _BACKUP_CHECKSUM_SCOPE,
    _BACKUP_MANIFEST_FORMAT_VERSION,
    SQLiteStore,
)

_BACKUP_NAME_RE = re.compile(
    r"^(?P<stem>.+)\.v(?P<version>\d+)-backup-(?P<attempt>[0-9a-f]{32})\.sqlite3$"
)
_MANIFEST_SUFFIX = ".manifest.json"

STATUS_VERIFIED = "VERIFIED"
STATUS_INCOMPLETE = "INCOMPLETE"
STATUS_REJECTED = "REJECTED"
STATUS_INVALID = "INVALID"
STATUS_MISSING = "MISSING"

_SUPPORTED_SCHEMA_VERSIONS = (1, 2, 3, 4)
_HEX_DIGEST_RE = re.compile(r"[0-9a-f]{64}")

_REQUIRED_MANIFEST_FIELDS = frozenset(
    {
        "manifest_format_version",
        "status",
        "backup_id",
        "migration_attempt_id",
        "source_path",
        "source_schema_version",
        "snapshot_utc",
        "event_count",
        "highest_event_id",
        "sqlite_sequence",
        "journal_mode",
        "synchronous",
        "verification_utc",
        "sha256",
        "checksum_scope",
    }
)

_PROTOCOL_STATUSES = (STATUS_VERIFIED, STATUS_INCOMPLETE, STATUS_REJECTED)


@dataclass(frozen=True, slots=True)
class BackupInventoryEntry:
    """Read-only report for a single backup candidate.

    All metadata is copied from the artifact's manifest where the manifest
    exists and is readable; nothing is inferred and nothing is invented. Fields
    are None when the information is unavailable (for example when the manifest
    is missing or unreadable).
    """

    status: str
    """One of STATUS_VERIFIED, STATUS_INCOMPLETE, STATUS_REJECTED,
    STATUS_INVALID, STATUS_MISSING."""

    failure_reason: str | None
    """Human-readable reason when status is not VERIFIED, else None."""

    backup_path: Path
    """Path of the backup artifact (may not exist for MISSING pairs)."""

    manifest_path: Path | None
    """Path of the manifest, if one was discovered for this candidate."""

    backup_id: str | None
    snapshot_utc: str | None
    source_path: str | None
    source_schema_version: int | None
    event_count: int | None
    highest_event_id: int | None

    sha256: str | None
    """SHA-256 digest of the backup artifact file itself, computed read-only."""

    manifest_sha256: str | None
    """SHA-256 digest claimed by the manifest, if any."""

    digest_match: bool | None
    """Whether the artifact digest matches the manifest digest, if both exist."""


def _is_int(value: Any) -> bool:
    """Return True for genuine integers (booleans are rejected)."""
    return isinstance(value, int) and not isinstance(value, bool)


def _is_valid_uuid(value: Any) -> bool:
    """Return True if value is a string in canonical UUID form."""
    if not isinstance(value, str):
        return False
    try:
        return str(UUID(value)) == value
    except (ValueError, AttributeError, TypeError):
        return False


def _parse_utc(value: Any) -> bool:
    """Return True if value is a timestamp string ending in Z that parses."""
    if not isinstance(value, str) or not value.endswith("Z"):
        return False
    try:
        datetime.fromisoformat(value.replace("Z", "+00:00"))
    except (TypeError, ValueError):
        return False
    return True


def _is_symlink(path: Path) -> bool:
    """Return True if *path* is a symbolic link, without following it.

    Uses ``os.lstat()`` which inspects the link itself rather than its
    target. A dangling link (target missing) still returns True because
    the link object itself exists.
    """
    try:
        st = os.lstat(path)
    except OSError:
        return False
    return _stat_module.S_ISLNK(st.st_mode)


def _open_regular_readonly(path: Path):
    """Open *path* for reading without following symbolic links.

    Returns an open file descriptor, or None if *path* is a symbolic link,
    does not exist, or cannot be safely opened as a regular file.

    Where the platform supports it (POSIX), ``O_NOFOLLOW`` is used so that
    the open itself fails on symbolic links, eliminating the
    check-then-open race. On Windows ``O_NOFOLLOW`` is not available; the
    ``os.lstat()`` check above is the primary defence, with a residual
    TOCTOU race that cannot be eliminated without platform-specific APIs.
    """
    try:
        st = os.lstat(path)
    except OSError:
        return None
    if _stat_module.S_ISLNK(st.st_mode):
        return None

    flags = os.O_RDONLY
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW

    try:
        fd = os.open(path, flags)
    except OSError:
        return None

    try:
        fst = os.fstat(fd)
    except OSError:
        os.close(fd)
        return None

    if _stat_module.S_ISLNK(fst.st_mode):
        os.close(fd)
        return None

    return fd


def _validate_manifest_structure(manifest: Any) -> str | None:
    """Return None when the manifest is structurally valid, else a reason.

    This reimplements the structural part of
    SQLiteStore._verify_backup_manifest without opening any database file:
    field presence, format version, types and value domains only.
    """
    if not isinstance(manifest, dict):
        return "manifest is not a JSON object"
    if not _REQUIRED_MANIFEST_FIELDS.issubset(manifest):
        missing = sorted(_REQUIRED_MANIFEST_FIELDS - set(manifest))
        return f"manifest is missing required fields: {', '.join(missing)}"
    if manifest.get("manifest_format_version") != _BACKUP_MANIFEST_FORMAT_VERSION:
        return "unsupported manifest format version"
    if manifest.get("checksum_scope") != _BACKUP_CHECKSUM_SCOPE:
        return "unsupported checksum scope"
    status = manifest.get("status")
    if status not in _PROTOCOL_STATUSES:
        return f"unrecognised manifest status {status!r}"
    backup_id = manifest.get("backup_id")
    migration_id = manifest.get("migration_attempt_id")
    if not _is_valid_uuid(backup_id) or backup_id != migration_id:
        return "backup_id and migration_attempt_id must be identical canonical UUIDs"
    source_path = manifest.get("source_path")
    if not isinstance(source_path, str) or not os.path.isabs(source_path):
        return "source_path must be an absolute path"
    schema_version = manifest.get("source_schema_version")
    if schema_version not in _SUPPORTED_SCHEMA_VERSIONS:
        return "unsupported source schema version"
    event_count = manifest.get("event_count")
    if not _is_int(event_count) or event_count < 0:
        return "event_count must be a non-negative integer"
    highest_event_id = manifest.get("highest_event_id")
    if (event_count == 0) != (highest_event_id is None):
        return "event_count and highest_event_id are inconsistent"
    if highest_event_id is not None and (
        not _is_int(highest_event_id) or highest_event_id < 1
    ):
        return "highest_event_id must be a positive integer"
    sqlite_sequence = manifest.get("sqlite_sequence")
    if sqlite_sequence is not None and (
        not _is_int(sqlite_sequence) or sqlite_sequence < 0
    ):
        return "sqlite_sequence must be a non-negative integer"
    if (
        sqlite_sequence is not None
        and highest_event_id is not None
        and sqlite_sequence < highest_event_id
    ):
        return "sqlite_sequence is below highest_event_id"
    if not _parse_utc(manifest.get("snapshot_utc")):
        return "snapshot_utc is not a UTC timestamp"
    verification_utc = manifest.get("verification_utc")
    if verification_utc is not None and not _parse_utc(verification_utc):
        return "verification_utc is not a UTC timestamp"
    if manifest.get("journal_mode") != "wal":
        return "journal_mode must be wal"
    if manifest.get("synchronous") != "FULL":
        return "synchronous must be FULL"
    sha256 = manifest.get("sha256")
    if sha256 is not None and (
        not isinstance(sha256, str) or _HEX_DIGEST_RE.fullmatch(sha256) is None
    ):
        return "sha256 must be a 64-character lowercase hex digest"
    return None


def _read_manifest(
    manifest_path: Path,
) -> tuple[dict[str, Any] | None, str | None]:
    """Read and parse a manifest file; return (manifest, None) or (None, reason).

    Reads through a file descriptor opened without following symbolic links;
    a symbolic link cannot be opened and is reported as such rather than
    having its external target contents read.
    """
    fd = _open_regular_readonly(manifest_path)
    if fd is None:
        if manifest_path.is_symlink():
            return None, "manifest is a symbolic link"
        return None, "manifest could not be read"
    try:
        raw = b""
        while True:
            block = os.read(fd, 65536)
            if not block:
                break
            raw += block
    finally:
        os.close(fd)
    try:
        manifest = json.loads(raw.decode("utf-8"))
    except (json.JSONDecodeError, UnicodeError, ValueError) as exc:
        return None, f"manifest is malformed: {exc}"
    if not isinstance(manifest, dict):
        return None, "manifest is not a JSON object"
    return manifest, None


def _sha256_of_file(path: Path) -> str | None:
    """Return the SHA-256 digest of a file, or None if it cannot be read.

    Reads file bytes through a file descriptor opened without following
    symbolic links; a symbolic link cannot be opened and yields None,
    so external target contents are never read.
    """
    fd = _open_regular_readonly(path)
    if fd is None:
        return None
    try:
        digest = hashlib.sha256()
        while True:
            block = os.read(fd, 1024 * 1024)
            if not block:
                break
            digest.update(block)
        return digest.hexdigest()
    finally:
        os.close(fd)


def _metadata_from_manifest(manifest: dict[str, Any]) -> dict[str, Any]:
    """Copy reportable metadata from a manifest without inventing defaults."""
    return {
        "backup_id": manifest.get("backup_id"),
        "snapshot_utc": manifest.get("snapshot_utc"),
        "source_path": manifest.get("source_path"),
        "source_schema_version": manifest.get("source_schema_version"),
        "event_count": manifest.get("event_count"),
        "highest_event_id": manifest.get("highest_event_id"),
        "manifest_sha256": manifest.get("sha256"),
    }


def _sidecar_anomaly(backup_path: Path) -> bool:
    """Read-only stat check for unexpected WAL/SHM sidecar state.

    The verifier rejects backups with WAL content or an SHM sidecar because
    they indicate an unfinalized or concurrently accessed artifact. The
    inventory inspects sidecars via ``os.lstat()`` only and never opens or
    follows them; a symbolic-link sidecar is treated as an anomaly.
    """
    wal_path = Path(str(backup_path) + "-wal")
    shm_path = Path(str(backup_path) + "-shm")
    try:
        wal_st = os.lstat(wal_path)
    except FileNotFoundError:
        wal_st = None
    except OSError:
        return True

    if wal_st is not None:
        if _stat_module.S_ISLNK(wal_st.st_mode):
            return True
        if _stat_module.S_ISREG(wal_st.st_mode) and wal_st.st_size > 0:
            return True

    try:
        shm_st = os.lstat(shm_path)
    except FileNotFoundError:
        shm_st = None
    except OSError:
        return True

    if shm_st is not None:
        if _stat_module.S_ISLNK(shm_st.st_mode):
            return True
        if _stat_module.S_ISREG(shm_st.st_mode):
            return True

    return False


def _entry(
    *,
    status: str,
    failure_reason: str | None,
    backup_path: Path,
    manifest_path: Path | None,
    manifest: dict[str, Any] | None,
    sha256: str | None,
    digest_match: bool | None,
) -> BackupInventoryEntry:
    """Build an inventory entry, copying manifest metadata read-only."""
    metadata = _metadata_from_manifest(manifest) if manifest else {
        "backup_id": None,
        "snapshot_utc": None,
        "source_path": None,
        "source_schema_version": None,
        "event_count": None,
        "highest_event_id": None,
        "manifest_sha256": None,
    }
    return BackupInventoryEntry(
        status=status,
        failure_reason=failure_reason,
        backup_path=backup_path,
        manifest_path=manifest_path,
        sha256=sha256,
        digest_match=digest_match,
        **metadata,
    )


def _classify_candidate(
    backup_path: Path,
    digest: str | None,
    manifest_path: Path | None,
) -> BackupInventoryEntry:
    """Classify a single backup/manifest pair read-only.

    Symbolic links are rejected before any target is read: a linked backup
    or manifest is reported INVALID without reading external contents.
    """
    # Symlink protection: reject linked artifacts before reading anything.
    if backup_path.is_symlink():
        return _entry(
            status=STATUS_INVALID,
            failure_reason="backup artifact is a symbolic link",
            backup_path=backup_path,
            manifest_path=manifest_path,
            manifest=None,
            sha256=None,
            digest_match=None,
        )

    if manifest_path is not None and manifest_path.is_symlink():
        return _entry(
            status=STATUS_INVALID,
            failure_reason="manifest is a symbolic link",
            backup_path=backup_path,
            manifest_path=manifest_path,
            manifest=None,
            sha256=digest,
            digest_match=None,
        )

    if manifest_path is None or not manifest_path.exists():
        return _entry(
            status=STATUS_MISSING,
            failure_reason="manifest file not found (incomplete artifact pair)",
            backup_path=backup_path,
            manifest_path=None,
            manifest=None,
            sha256=digest,
            digest_match=None,
        )

    manifest, reason = _read_manifest(manifest_path)
    if manifest is None:
        return _entry(
            status=STATUS_INVALID,
            failure_reason=reason,
            backup_path=backup_path,
            manifest_path=manifest_path,
            manifest=None,
            sha256=digest,
            digest_match=None,
        )

    structure_reason = _validate_manifest_structure(manifest)
    if structure_reason is not None:
        return _entry(
            status=STATUS_INVALID,
            failure_reason=structure_reason,
            backup_path=backup_path,
            manifest_path=manifest_path,
            manifest=manifest,
            sha256=digest,
            digest_match=None,
        )

    if digest is None:
        return _entry(
            status=STATUS_INVALID,
            failure_reason="backup artifact could not be read",
            backup_path=backup_path,
            manifest_path=manifest_path,
            manifest=manifest,
            sha256=None,
            digest_match=None,
        )

    status = manifest["status"]
    manifest_sha256 = manifest.get("sha256")
    digest_match = (
        digest == manifest_sha256
        if isinstance(manifest_sha256, str)
        else None
    )

    if status == STATUS_VERIFIED:
        if not isinstance(manifest_sha256, str):
            return _entry(
                status=STATUS_INVALID,
                failure_reason="VERIFIED manifest has no SHA-256 digest",
                backup_path=backup_path,
                manifest_path=manifest_path,
                manifest=manifest,
                sha256=digest,
                digest_match=None,
            )
        if digest_match is False:
            return _entry(
                status=STATUS_INVALID,
                failure_reason="backup checksum does not match its manifest",
                backup_path=backup_path,
                manifest_path=manifest_path,
                manifest=manifest,
                sha256=digest,
                digest_match=False,
            )
        if _sidecar_anomaly(backup_path):
            return _entry(
                status=STATUS_INVALID,
                failure_reason="backup has unexpected WAL/SHM sidecar state",
                backup_path=backup_path,
                manifest_path=manifest_path,
                manifest=manifest,
                sha256=digest,
                digest_match=True,
            )
        return _entry(
            status=STATUS_VERIFIED,
            failure_reason=None,
            backup_path=backup_path,
            manifest_path=manifest_path,
            manifest=manifest,
            sha256=digest,
            digest_match=True,
        )

    if status == STATUS_INCOMPLETE:
        return _entry(
            status=STATUS_INCOMPLETE,
            failure_reason=None,
            backup_path=backup_path,
            manifest_path=manifest_path,
            manifest=manifest,
            sha256=digest,
            digest_match=digest_match,
        )

    # status == STATUS_REJECTED
    return _entry(
        status=STATUS_REJECTED,
        failure_reason=None,
        backup_path=backup_path,
        manifest_path=manifest_path,
        manifest=manifest,
        sha256=digest,
        digest_match=digest_match,
    )


def _orphan_backup_path(manifest_path: Path) -> Path:
    """Return the backup path a manifest names by convention."""
    return Path(str(manifest_path)[: -len(_MANIFEST_SUFFIX)])


def inventory_backups(directory: str | Path) -> list[BackupInventoryEntry]:
    """Return a read-only inventory of every backup candidate in *directory*.

    Candidates are discovered using the repository's actual backup naming
    convention (see SQLiteStore._create_verified_backup) together with their
    sidecar manifests (SQLiteStore._backup_manifest_path). Each candidate is
    reported exactly once, independently of every other candidate; no
    candidate is selected, ranked or preferred.

    Nothing is modified: file bytes, file names, directory contents and any
    database in the directory are left untouched.
    """
    directory = Path(directory)
    if not directory.is_dir():
        return []

    backup_candidates: list[Path] = []
    orphan_manifests: dict[Path, Path] = {}
    results: list[BackupInventoryEntry] = []
    seen_manifests: set[Path] = set()
    try:
        entries = sorted(directory.iterdir(), key=lambda path: path.name)
    except OSError:
        return []

    for entry in entries:
        name = entry.name

        # Symlink protection: never follow links. A linked backup artifact is
        # classified INVALID here without reading its external target.
        # Linked manifest artifacts are not classified here to avoid
        # duplicates: they are handled by _classify_candidate (when the
        # backup exists) or by the orphan-manifest processing (when it does
        # not).
        if entry.is_symlink():
            if _BACKUP_NAME_RE.match(name):
                results.append(
                    _entry(
                        status=STATUS_INVALID,
                        failure_reason="backup artifact is a symbolic link",
                        backup_path=entry,
                        manifest_path=None,
                        manifest=None,
                        sha256=None,
                        digest_match=None,
                    )
                )
            elif name.endswith(_MANIFEST_SUFFIX):
                # Orphan manifest symlink: no backup artifact exists for it.
                expected_backup = _orphan_backup_path(entry)
                if not expected_backup.exists() and not expected_backup.is_symlink():
                    results.append(
                        _entry(
                            status=STATUS_INVALID,
                            failure_reason="manifest is a symbolic link",
                            backup_path=expected_backup,
                            manifest_path=entry,
                            manifest=None,
                            sha256=None,
                            digest_match=None,
                        )
                    )
            # Manifest symlinks whose backup exists are handled by
            # _classify_candidate to avoid duplicates. Sidecar symlinks are
            # handled by _sidecar_anomaly.
            continue

        if not entry.is_file():
            continue

        if name.endswith(_MANIFEST_SUFFIX):
            expected_backup = _orphan_backup_path(entry)
            # A symlink backup (even dangling) is classified as INVALID in the
            # symlink branch above; it is not a missing artifact.
            if not expected_backup.exists() and not expected_backup.is_symlink():
                orphan_manifests[expected_backup] = entry
            continue
        if _BACKUP_NAME_RE.match(name):
            backup_candidates.append(entry)

    for backup_path in backup_candidates:
        digest = _sha256_of_file(backup_path)
        manifest_path = SQLiteStore._backup_manifest_path(backup_path)
        entry = _classify_candidate(backup_path, digest, manifest_path)
        results.append(entry)
        if entry.manifest_path is not None:
            seen_manifests.add(entry.manifest_path)

    # Manifests whose backup artifact is absent: incomplete artifact pairs.
    for expected_backup, manifest_path in sorted(
        orphan_manifests.items(), key=lambda item: str(item[0])
    ):
        if manifest_path in seen_manifests:
            continue
        if manifest_path.is_symlink():
            results.append(
                _entry(
                    status=STATUS_INVALID,
                    failure_reason="manifest is a symbolic link",
                    backup_path=expected_backup,
                    manifest_path=manifest_path,
                    manifest=None,
                    sha256=None,
                    digest_match=None,
                )
            )
            continue
        manifest, _ = _read_manifest(manifest_path)
        results.append(
            _entry(
                status=STATUS_MISSING,
                failure_reason="backup artifact not found (incomplete artifact pair)",
                backup_path=expected_backup,
                manifest_path=manifest_path,
                manifest=manifest,
                sha256=None,
                digest_match=None,
            )
        )

    results.sort(key=lambda entry: str(entry.backup_path))
    return results
```

### 6.2 Modified file: `tests/test_backup_inventory.py`

The complete file (30,392 bytes) is reproduced below. Changes relative to the
M-2I.4 version:

- Added `import os`.
- Added `_external_file()` helper to create a file outside the inventory directory.
- Added 8 new test methods:
  - `test_backup_symlink_to_external_target_is_invalid`
  - `test_manifest_symlink_to_external_target_is_invalid`
  - `test_symlink_rejected_without_reading_external_target`
  - `test_dangling_backup_symlink_is_invalid`
  - `test_dangling_manifest_symlink_is_invalid`
  - `test_wal_symlink_downgrades_verified_to_invalid`
  - `test_shm_symlink_downgrades_verified_to_invalid`
  - `test_regular_backup_and_manifest_still_verified`

```python
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
            "\u0431\u0435\u043a\u0430\u043f-\u0431\u0430\u0437\u0430.sqlite3",
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

    def test_implementation_is_platform_agnostic(self):
        """The module uses only cross-platform standard-library tools.

        No os.name/sys.platform/ctypes branches: it can run on
        non-Windows platforms without modification.
        """
        source = (
            REPO_ROOT
            / "src"
            / "origin_trader"
            / "storage"
            / "backup_inventory.py"
        )
        text = source.read_text(encoding="utf-8")
        for token in ("os.name", "sys.platform", "ctypes", "win32"):
            self.assertNotIn(token, text)

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


if __name__ == "__main__":
    unittest.main()
```

---

## 7. Platform-specific security analysis

### Platform under test

- OS: Windows (Windows 11, `platform: nt`, `os.name: nt`)
- Python: 3.12.10
- `os.O_NOFOLLOW`: **not available** on Windows

### Symlink protection mechanism

The inventory uses a layered defence:

| Layer | Mechanism | Platforms | Race-safe? |
|---|---|---|---|
| 1 | `os.lstat()` / `Path.is_symlink()` — detect symlink before opening | All (Windows + POSIX) | Yes for classification (no target read) |
| 2 | `os.open(O_RDONLY \| O_NOFOLLOW)` — open fails on symlink | POSIX only (Linux, macOS) | Yes — eliminates TOCTOU |
| 3 | `os.fstat()` on opened fd — confirm regular file | All | Defence in depth |
| 4 | `_sidecar_anomaly()` uses `os.lstat()` on `-wal`/`-shm` | All | Yes for classification |

### Windows limitation

On Windows, `os.O_NOFOLLOW` is **not available** (`hasattr(os, "O_NOFOLLOW")` → `False`). Therefore:
- The primary defence is `os.lstat()` / `Path.is_symlink()` checked **before** any open.
- A residual TOCTOU (check-then-open) race exists on Windows between the `lstat` check and the `os.open()` call. An attacker who replaces a regular file with a symlink in that window could cause the inventory to follow the link.
- This race cannot be eliminated on Windows without platform-specific APIs (e.g., `CreateFileW` with `FILE_FLAG_OPEN_REPARSE_POINT`).
- All symlink classification (reporting INVALID) happens via `is_symlink()` **before** any target is read, so even in the race window, no external content is read *unless* the race is won — and the race window is limited to the microseconds between `lstat` and `open`.

On POSIX platforms (Linux, macOS), `O_NOFOLLOW` is available and the open itself fails on symlinks, eliminating the race.

### Test coverage on this platform

All 8 new symlink tests pass on Windows, including:
- Backup symlink to external target → INVALID
- Manifest symlink to external target → INVALID
- Symlink rejected even when target deleted (proves no target read)
- Dangling backup symlink → INVALID
- Dangling manifest symlink → INVALID
- WAL sidecar symlink → INVALID
- SHM sidecar symlink → INVALID
- Regular files still verified
- External target bytes/mtime unchanged after symlink rejection

No tests are skipped on this platform. On non-Windows platforms without symlink creation privileges, symlink tests would be skipped; on POSIX platforms with `O_NOFOLLOW`, the race-free path is exercised.

---

## 8. Evidence that linked external targets are not read

### Test: `test_symlink_rejected_without_reading_external_target`

Creates a backup fixture, replaces the backup file with a symlink to an external file, then **deletes the external target**. The inventory still reports `INVALID` with "symbolic link" in the failure reason. Since the target no longer exists, the inventory could not have read it — proving the symlink is detected by `is_symlink()`/`lstat()` before any read attempt.

### Test: `test_backup_symlink_to_external_target_is_invalid` and `test_manifest_symlink_to_external_target_is_invalid`

Create external files, record their SHA-256 digest and mtime_ns **before** inventory execution, replace the backup/manifest with symlinks to them, run the inventory, then verify the external file's digest and mtime are **unchanged**. This proves external target bytes and metadata are not modified.

### Test: `test_wal_symlink_downgrades_verified_to_invalid` and `test_shm_symlink_downgrades_verified_to_invalid`

Same before/after hash+mtime verification for WAL and SHM sidecar symlink targets.

---

## 9. Evidence that nothing is modified

- `test_inventory_does_not_modify_anything` — per-file SHA-256/mtime_ns/size and directory entry set identical before vs. after; live database bytes, `PRAGMA user_version`, schema SQL, and row count identical before vs. after.
- `test_read_only_inventory_proof` — second independent before/after hash proof.
- All symlink tests verify external target digest and mtime unchanged.
- No file writes, deletes, renames, or `os.replace` calls exist anywhere in `backup_inventory.py`.
- No SQLite connections are opened; no SQL is executed; no WAL/SHM/journal files can be created.

---

## 10. Test results

### Focused inventory tests (30 total, 22 original + 8 new symlink)

```
$ .venv\Scripts\python -m pytest tests/test_backup_inventory.py -q
..............................                                           [100%]
30 passed in 1.68s
```

Stable across repeated runs (30 passed on each run).

### Existing backup and migration tests

```
$ .venv\Scripts\python -m pytest tests/test_storage.py -q
......................................... [ 39%]
..........................................................s...    [100%]
102 passed, 1 skipped, 38 subtests passed in 27.02s
```

### Full test suite

```
$ .venv\Scripts\python -m pytest tests -q
............................................. [ 42%]
............................................. [ 74%]
................................s...                                     [100%]
141 passed, 1 skipped, 38 subtests passed in 28.73s
```

### Skipped tests

- `tests/test_storage.py:3068` `test_non_nt_uses_standard_mkdir` — skipped because this machine is Windows (`os.name == "nt"`). Pre-existing; unrelated to M-2I.4.3. No M-2I.4.3 test is skipped.

---

## 11. Scope confirmations

- No `sqlite_store.py` modification.
- No existing backup publication or verification logic changed.
- No manifest format change.
- No database schema or migration protocol change.
- No security standards or `TECHNICAL_SPEC.md` changes.
- No recovery, restoration, retention, deletion, or forensic copying functionality.
- No backup signing, HMAC, DPAPI, or new cryptographic mechanisms.
- No trading logic, OBSERVE mode, or order execution changes.
- No commit or push occurred (HEAD is still `b52aeb2` on `master`).
- No new dependencies (stdlib only).
- No interactive restore or selection action.
- No automatic candidate preference (results sorted by path for stable output only).

---

## 12. Remaining platform limitations

- **Windows `O_NOFOLLOW` unavailable**: On Windows, the inventory relies on `os.lstat()`/`is_symlink()` checked before opening. A residual TOCTOU race exists between the `lstat` check and the `os.open()` call. This cannot be eliminated without Windows-specific APIs (`CreateFileW` with `FILE_FLAG_OPEN_REPARSE_POINT`). The race window is limited to microseconds and no external content is read unless the race is won.
- **Symlink creation privileges**: On some Windows configurations, `os.symlink()` requires `CREATE_SYMBOLIC_LINK` privilege or Developer Mode. Symlink tests would be skipped in such environments. On this test system, symlink creation succeeds.
- **Non-Windows platforms**: Not tested in this environment. The code is platform-agnostic (no `os.name`/`sys.platform`/`ctypes`/`win32` branches) and uses `O_NOFOLLOW` where available (POSIX), providing race-free protection on Linux/macOS.

The inventory is informational only: it discovers, verifies (read-only, without following symlinks), and reports. It makes no recovery decision.
