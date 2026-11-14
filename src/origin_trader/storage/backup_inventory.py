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

if os.name == "nt":
    import ctypes
    from ctypes import wintypes
    import msvcrt

    _kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)

    # Windows API constants
    GENERIC_READ = 0x80000000
    FILE_SHARE_READ = 0x00000001
    OPEN_EXISTING = 3
    FILE_FLAG_OPEN_REPARSE_POINT = 0x00200000
    FILE_FLAG_BACKUP_SEMANTICS = 0x02000000
    FILE_ATTRIBUTE_REPARSE_POINT = 0x00000400
    FILE_ATTRIBUTE_DIRECTORY = 0x00000010
    INVALID_HANDLE_VALUES = (-1, 0, 0xFFFFFFFF, 0xFFFFFFFFFFFFFFFF)
    FileBasicInfo = 0

    # Windows API structures
    class FILETIME(ctypes.Structure):
        _fields_ = [
            ("dwLowDateTime", wintypes.DWORD),
            ("dwHighDateTime", wintypes.DWORD),
        ]

    class FILE_BASIC_INFO(ctypes.Structure):
        _fields_ = [
            ("CreationTime", FILETIME),
            ("LastAccessTime", FILETIME),
            ("LastWriteTime", FILETIME),
            ("ChangeTime", FILETIME),
            ("DwFileAttributes", wintypes.DWORD),
        ]

    # Windows API function signatures
    _kernel32.GetFileAttributesW.argtypes = [wintypes.LPCWSTR]
    _kernel32.GetFileAttributesW.restype = wintypes.DWORD

    _kernel32.CreateFileW.argtypes = [
        wintypes.LPCWSTR,
        wintypes.DWORD,
        wintypes.DWORD,
        wintypes.LPVOID,
        wintypes.DWORD,
        wintypes.DWORD,
        wintypes.HANDLE,
    ]
    _kernel32.CreateFileW.restype = wintypes.HANDLE

    _kernel32.GetFileInformationByHandle.argtypes = [
        wintypes.HANDLE,
        wintypes.LPVOID,
    ]
    _kernel32.GetFileInformationByHandle.restype = wintypes.BOOL

    _kernel32.CloseHandle.argtypes = [wintypes.HANDLE]
    _kernel32.CloseHandle.restype = wintypes.BOOL

    # BY_HANDLE_FILE_INFORMATION structure (used by GetFileInformationByHandle)
    class BY_HANDLE_FILE_INFORMATION(ctypes.Structure):
        _fields_ = [
            ("dwFileAttributes", wintypes.DWORD),
            ("ftCreationTime", FILETIME),
            ("ftLastAccessTime", FILETIME),
            ("ftLastWriteTime", FILETIME),
            ("dwVolumeSerialNumber", wintypes.DWORD),
            ("nFileSizeHigh", wintypes.DWORD),
            ("nFileSizeLow", wintypes.DWORD),
            ("nNumberOfLinks", wintypes.DWORD),
            ("nFileIndexHigh", wintypes.DWORD),
            ("nFileIndexLow", wintypes.DWORD),
        ]

# Backup artifact naming convention (see SQLiteStore._create_verified_backup):
#   {database_name}.v{version}-backup-{32-hex-attempt-id}.sqlite3
_BACKUP_NAME_RE = re.compile(
    r"^(?P<stem>.+)\.v(?P<version>\d+)-backup-(?P<attempt>[0-9a-f]{32})\.sqlite3$"
)
_MANIFEST_SUFFIX = ".manifest.json"

# Status values reported by the inventory.
STATUS_VERIFIED = "VERIFIED"
STATUS_INCOMPLETE = "INCOMPLETE"
STATUS_REJECTED = "REJECTED"
STATUS_INVALID = "INVALID"
STATUS_MISSING = "MISSING"

_SUPPORTED_SCHEMA_VERSIONS = (1, 2, 3, 4)
_HEX_DIGEST_RE = re.compile(r"[0-9a-f]{64}")

# Fields every manifest must contain (same set as
# SQLiteStore._verify_backup_manifest).
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

# Manifest statuses the backup protocol itself produces.
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


def _open_regular_readonly_posix(path: Path):
    """Open *path* for reading without following symbolic links (POSIX).

    Returns an open file descriptor, or None if *path* is a symbolic link,
    does not exist, or is not a regular file.

    ``O_NOFOLLOW`` is used where supported so the open itself fails on
    symbolic links, eliminating the check-then-open race. ``O_NONBLOCK``
    is used where supported so opening special files (FIFOs, devices)
    does not block. The opened descriptor is validated with ``os.fstat()``
    and ``stat.S_ISREG()`` before being returned.
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
    if hasattr(os, "O_NONBLOCK"):
        flags |= os.O_NONBLOCK

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

    if not _stat_module.S_ISREG(fst.st_mode):
        os.close(fd)
        return None

    return fd


def _open_regular_readonly_windows(path: Path):
    """Open *path* for reading without following reparse points (Windows).

    Returns an open file descriptor, or None if *path* is a reparse point
    (symbolic link, junction, mount point, etc.), does not exist, or is not
    a regular file.

    Uses ``GetFileAttributesW`` to detect reparse points without opening
    them, then ``CreateFileW`` with ``FILE_FLAG_OPEN_REPARSE_POINT`` to open
    the object itself rather than its target. The opened handle is validated
    with ``GetFileInformationByHandle`` and converted to a C file
    descriptor via ``msvcrt.open_osfhandle``.

    A single-ownership model is used: the Windows HANDLE is owned by this
    function until either it is rejected (and closed in the ``finally``
    block) or ownership is transferred to a C file descriptor via
    ``msvcrt.open_osfhandle()``.
    """
    hFile = None
    handle_owned = False
    try:
        attrs = _kernel32.GetFileAttributesW(str(path))
        if attrs == 0xFFFFFFFF:  # INVALID_FILE_ATTRIBUTES
            return None
        if attrs & FILE_ATTRIBUTE_REPARSE_POINT:
            return None
        if attrs & FILE_ATTRIBUTE_DIRECTORY:
            return None

        hFile = _kernel32.CreateFileW(
            str(path),
            GENERIC_READ,
            FILE_SHARE_READ,
            None,
            OPEN_EXISTING,
            FILE_FLAG_OPEN_REPARSE_POINT | FILE_FLAG_BACKUP_SEMANTICS,
            None,
        )
        handle_value = int(hFile)
        if handle_value in INVALID_HANDLE_VALUES:
            hFile = None
            return None
        handle_owned = True

        info = BY_HANDLE_FILE_INFORMATION()
        if not _kernel32.GetFileInformationByHandle(
            hFile, ctypes.byref(info)
        ):
            return None
        if info.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY:
            return None
        if info.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT:
            return None

        fd = msvcrt.open_osfhandle(handle_value, os.O_RDONLY)
        handle_owned = False  # ownership transferred to fd
        return fd
    finally:
        if handle_owned and hFile is not None:
            _kernel32.CloseHandle(hFile)


def _is_windows_reparse_point(path: Path) -> bool:
    """Return True if *path* is a Windows reparse point, without opening it.

    Uses ``GetFileAttributesW`` to inspect the object's attributes.
    Returns False on non-Windows platforms or when the attribute cannot be
    read.
    """
    if os.name != "nt":
        return False
    try:
        attrs = _kernel32.GetFileAttributesW(str(path))
    except OSError:
        return False
    if attrs == 0xFFFFFFFF:  # INVALID_FILE_ATTRIBUTES
        return False
    return bool(attrs & FILE_ATTRIBUTE_REPARSE_POINT)


def _open_regular_readonly(path: Path):
    """Open *path* for reading without following symbolic links or reparse points.

    Returns an open file descriptor, or None if *path* is a link, does not
    exist, or is not a regular file. Dispatches to the platform-specific
    implementation.
    """
    if os.name == "nt":
        return _open_regular_readonly_windows(path)
    return _open_regular_readonly_posix(path)


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
    follows them; a symbolic-link sidecar, Windows reparse-point sidecar,
    or any non-regular WAL sidecar is treated as an anomaly. Any existing
    SHM sidecar is treated as an anomaly, consistent with the existing
    backup verifier.
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
        if _is_windows_reparse_point(wal_path):
            return True
        if not _stat_module.S_ISREG(wal_st.st_mode):
            return True
        if wal_st.st_size > 0:
            return True

    try:
        shm_st = os.lstat(shm_path)
    except FileNotFoundError:
        shm_st = None
    except OSError:
        return True

    # Any existing SHM sidecar is rejected, consistent with the existing
    # backup verifier (_assert_backup_sidecars with inspect_shm=True).
    if shm_st is not None:
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
