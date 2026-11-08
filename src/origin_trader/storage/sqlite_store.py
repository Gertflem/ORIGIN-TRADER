"""SQLite persistence engine for ORIGIN TRADER."""

from collections.abc import Mapping
from dataclasses import dataclass
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import re
import sqlite3
from typing import Any
from uuid import UUID, uuid4


SCHEMA_VERSION = 4
_V3_SCHEMA_VERSION = 3
_V2_SCHEMA_VERSION = 2

_UPDATE_TRIGGER = "system_events_reject_update"
_DELETE_TRIGGER = "system_events_reject_delete"
_IDEMPOTENCY_TRIGGER = "system_events_require_idempotency_key"
_IDEMPOTENCY_INDEX = "system_events_idempotency_key_uq"
_V1_TABLE_SQL = """
    CREATE TABLE system_events (
        event_id INTEGER PRIMARY KEY AUTOINCREMENT,
        event_type TEXT NOT NULL,
        occurred_at_utc TEXT NOT NULL,
        payload_json TEXT NOT NULL
    )
"""
_V2_TABLE_SQL = """
    CREATE TABLE system_events (
        event_id INTEGER PRIMARY KEY AUTOINCREMENT,
        event_type TEXT NOT NULL
            CHECK(length(trim(event_type)) > 0),
        occurred_at_utc TEXT NOT NULL,
        payload_json TEXT NOT NULL
    )
"""
_V3_TABLE_SQL = """
    CREATE TABLE system_events (
        event_id INTEGER PRIMARY KEY AUTOINCREMENT,
        event_type TEXT NOT NULL
            CHECK(length(trim(event_type)) > 0),
        occurred_at_utc TEXT NOT NULL,
        payload_json TEXT NOT NULL,
        idempotency_key TEXT
    )
"""

_IDEMPOTENCY_INDEX_SQL = f"""
    CREATE UNIQUE INDEX {_IDEMPOTENCY_INDEX}
    ON system_events (idempotency_key)
    WHERE idempotency_key IS NOT NULL
"""
_IDEMPOTENCY_TRIGGER_SQL = f"""
    CREATE TRIGGER IF NOT EXISTS {_IDEMPOTENCY_TRIGGER}
    BEFORE INSERT ON system_events
    WHEN CASE
      WHEN NEW.idempotency_key IS NULL THEN 1
      WHEN typeof(NEW.idempotency_key) != 'text' THEN 1
      WHEN instr(CAST(NEW.idempotency_key AS BLOB), X'00') > 0 THEN 1
      WHEN length(NEW.idempotency_key) < 38 THEN 1
      WHEN length(NEW.idempotency_key) > 85 THEN 1
      WHEN instr(NEW.idempotency_key, ':') < 2 THEN 1
      WHEN instr(
          substr(NEW.idempotency_key, instr(NEW.idempotency_key, ':') + 1),
          ':'
      ) != 0 THEN 1
      WHEN length(
          substr(NEW.idempotency_key, 1,
                 instr(NEW.idempotency_key, ':') - 1)
      ) > 48 THEN 1
      WHEN substr(NEW.idempotency_key, 1, 1) NOT GLOB '[a-z]' THEN 1
      WHEN substr(NEW.idempotency_key, 1,
                  instr(NEW.idempotency_key, ':') - 1)
           GLOB '*[^a-z0-9-]*' THEN 1
      WHEN length(
          substr(NEW.idempotency_key, instr(NEW.idempotency_key, ':') + 1)
      ) != 36 THEN 1
      WHEN substr(NEW.idempotency_key, instr(NEW.idempotency_key, ':') + 1)
           NOT GLOB
           '[0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f]-[0-9a-f][0-9a-f][0-9a-f][0-9a-f]-[0-9a-f][0-9a-f][0-9a-f][0-9a-f]-[0-9a-f][0-9a-f][0-9a-f][0-9a-f]-[0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f]' THEN 1
      ELSE 0
    END
    BEGIN
        SELECT RAISE(ABORT, 'valid idempotency key required');
    END
"""
_IDEMPOTENCY_KEY_RE = re.compile(
    r"[a-z][a-z0-9-]{0,47}:"
    r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}",
    re.ASCII,
)

_CONNECTION_OPEN = "OPEN"
_CONNECTION_INVALID = "INVALID"
_CONNECTION_CLOSED = "CLOSED"
_BACKUP_MANIFEST_FORMAT_VERSION = 1
_BACKUP_CHECKSUM_SCOPE = "finalized-main-database-after-wal-truncate-and-close"


class StorageError(RuntimeError):
    """Raised when persistent storage cannot operate safely."""


class DatabaseMissingError(StorageError):
    """Raised when an expected database file does not exist."""


class IdempotencyConflictError(StorageError):
    """Raised when an idempotency key is reused for different event data."""


@dataclass(frozen=True, slots=True)
class StoredEvent:
    event_id: int
    event_type: str
    occurred_at_utc: str
    payload: dict[str, Any]
    idempotency_key: str | None = None


class SQLiteStore:
    """SQLite storage service with protected append-only events."""

    def __init__(self, database_path: str | Path):
        raw_path = str(database_path)

        if not raw_path.strip():
            raise ValueError("Database path cannot be empty.")

        if raw_path == ":memory:":
            raise StorageError(
                "In-memory databases must be explicitly created with "
                "SQLiteStore.initialize(':memory:')."
            )

        try:
            path = Path(raw_path).resolve()
            path.stat()
        except FileNotFoundError as exc:
            raise DatabaseMissingError(
                f"Expected database does not exist: {Path(raw_path)}"
            ) from exc
        except OSError as exc:
            raise StorageError(
                f"Could not inspect expected database path: {Path(raw_path)}"
            ) from exc

        self._database_path = path

        self._state = _CONNECTION_OPEN
        self._connection_close_succeeded = False
        self._cleanup_errors: list[BaseException] = []
        self._migration_reservation_active = False

        try:
            self._connection = self._connect_existing(path)
            self._configure_connection()
            self._initialize_schema()

        except DatabaseMissingError as exc:
            self._close_failed_connection(exc)
            raise
        except sqlite3.Error as exc:
            self._close_failed_connection(exc)
            try:
                path.stat()
            except FileNotFoundError as stat_exc:
                raise DatabaseMissingError(
                    f"Expected database does not exist: {path}"
                ) from stat_exc
            except OSError as stat_exc:
                raise StorageError(
                    f"Could not inspect expected database path: {path}"
                ) from stat_exc
            raise StorageError(f"Could not safely open database: {path}") from exc
        except BaseException as exc:
            self._close_failed_connection(exc)
            raise

    @staticmethod
    def _connect_existing(path: Path) -> sqlite3.Connection:
        """Open a database in read/write mode without SQLite create semantics."""

        uri = f"{path.as_uri()}?mode=rw"
        return sqlite3.connect(
            uri,
            uri=True,
            timeout=5.0,
            isolation_level=None,
        )

    def _configure_connection(self) -> None:
        self._connection.row_factory = sqlite3.Row
        self._connection.execute("PRAGMA foreign_keys = ON")
        self._connection.execute("PRAGMA busy_timeout = 5000")
        self._connection.execute("PRAGMA recursive_triggers = ON")
        self._connection.execute("PRAGMA locking_mode = NORMAL")
        self._verify_connection_setting("foreign_keys", 1)
        self._verify_connection_setting("busy_timeout", 5000)
        self._verify_connection_setting("locking_mode", "normal")
        recursive_triggers = self._connection.execute(
            "PRAGMA recursive_triggers"
        ).fetchone()[0]
        if recursive_triggers != 1:
            raise StorageError("SQLite recursive triggers could not be enabled.")

    def _verify_connection_setting(self, pragma: str, expected: int | str) -> None:
        value = self._connection.execute(f"PRAGMA {pragma}").fetchone()[0]
        if isinstance(expected, str):
            matches = str(value).lower() == expected.lower()
        else:
            matches = value == expected
        if not matches:
            raise StorageError(
                f"SQLite {pragma} setting is {value!r}; expected {expected!r}."
            )

    def _configure_durability(self, *, allow_transition: bool = False) -> None:
        mode = str(
            self._connection.execute("PRAGMA journal_mode").fetchone()[0]
        ).lower()
        if mode != "wal":
            if not allow_transition or mode != "delete":
                raise StorageError(
                    f"SQLite journal mode is {mode!r}; expected 'wal'."
                )
            mode = str(
                self._connection.execute("PRAGMA journal_mode = WAL").fetchone()[0]
            ).lower()
            if mode != "wal":
                raise StorageError(
                    f"SQLite could not enable WAL mode (effective mode: {mode!r})."
                )

        self._connection.execute("PRAGMA synchronous = FULL")
        self._verify_connection_setting("synchronous", 2)
        self._connection.execute("PRAGMA wal_autocheckpoint = 1000")
        self._verify_connection_setting("wal_autocheckpoint", 1000)

    def _verify_file_durability(self) -> None:
        mode = str(
            self._connection.execute("PRAGMA journal_mode").fetchone()[0]
        ).lower()
        if mode != "wal":
            raise StorageError(f"SQLite journal mode is {mode!r}; expected 'wal'.")
        self._verify_connection_setting("synchronous", 2)
        self._verify_connection_setting("wal_autocheckpoint", 1000)

    def _attempt_connection_close(
        self, cause: BaseException | None = None
    ) -> BaseException | None:
        if self._connection_close_succeeded:
            return None
        connection = getattr(self, "_connection", None)
        if connection is not None:
            try:
                connection.close()
            except BaseException as close_error:
                self._cleanup_errors.append(close_error)
                if cause is not None:
                    cause.add_note(
                        "SQLite connection cleanup also failed: "
                        f"{type(close_error).__name__}: {close_error}"
                    )
                return close_error
        self._connection_close_succeeded = True
        return None

    def _invalidate_connection(
        self,
        cause: BaseException | None = None,
        cleanup_errors: tuple[BaseException, ...] = (),
    ) -> None:
        if self._state == _CONNECTION_CLOSED:
            return
        self._state = _CONNECTION_INVALID
        for error in cleanup_errors:
            self._cleanup_errors.append(error)
            if cause is not None:
                description = (
                    self._sqlite_error_description(error)
                    if isinstance(error, sqlite3.Error)
                    else f"{type(error).__name__}: {error}"
                )
                cause.add_note(
                    "SQLite transaction cleanup also failed: " + description
                )
        self._attempt_connection_close(cause)

    def _close_failed_connection(self, cause: BaseException | None = None) -> None:
        self._invalidate_connection(cause)

    @classmethod
    def initialize(cls, database_path: str | Path) -> "SQLiteStore":
        """Deliberately create a new database and initialize its schema.

        Existing files are never overwritten. For file databases, O_EXCL makes
        creation a single-winner operation; a crash after file creation leaves
        an uninitialized file that normal opening will reject for review.
        """

        raw_path = str(database_path)
        if not raw_path.strip():
            raise ValueError("Database path cannot be empty.")

        store = cls.__new__(cls)
        store._state = _CONNECTION_OPEN
        store._connection_close_succeeded = False
        store._cleanup_errors = []
        store._migration_reservation_active = False
        store._database_path = None

        if raw_path == ":memory:":
            try:
                store._connection = sqlite3.connect(
                    ":memory:", timeout=5.0, isolation_level=None
                )
                store._configure_connection()
                store._connection.execute("PRAGMA synchronous = FULL")
                store._verify_connection_setting("synchronous", 2)
                store._connection.execute("PRAGMA wal_autocheckpoint = 1000")
                store._verify_connection_setting("wal_autocheckpoint", 1000)
                store._create_initial_schema()
                return store
            except BaseException as exc:
                store._close_failed_connection(exc)
                raise

        path = Path(raw_path)
        try:
            path.parent.mkdir(parents=True, exist_ok=True)
            path = path.resolve()
            descriptor = os.open(
                path,
                os.O_CREAT | os.O_EXCL | os.O_RDWR,
                0o600,
            )
            os.close(descriptor)
        except FileExistsError as exc:
            raise StorageError(
                f"Database already exists; refusing to initialize or overwrite: {path}"
            ) from exc
        except OSError as exc:
            raise StorageError(f"Could not create database file: {path}") from exc

        store._database_path = path
        try:
            store._connection = cls._connect_existing(path)
            store._configure_connection()
            store._configure_durability(allow_transition=True)
            store._create_initial_schema()
            return store
        except sqlite3.Error as exc:
            store._close_failed_connection(exc)
            raise StorageError(f"Could not initialize database: {path}") from exc
        except BaseException as exc:
            store._close_failed_connection(exc)
            raise

    def _create_initial_schema(self) -> None:
        """Create a new schema only through the explicit initialization path."""

        try:
            self._schema_transaction(self._connection)
            version = self._connection.execute(
                "PRAGMA user_version"
            ).fetchone()[0]
            objects = self._connection.execute(
                """
                SELECT name
                FROM sqlite_master
                WHERE name NOT LIKE 'sqlite_%'
                """
            ).fetchall()
            if version != 0 or objects:
                raise StorageError(
                    "Database is not empty; refusing initialization."
                )

            self._connection.execute(_V3_TABLE_SQL)
            self._install_append_only_triggers()
            self._install_idempotency_protection()
            self._connection.execute(
                f"PRAGMA user_version = {SCHEMA_VERSION}"
            )
            self._verify_schema(expected_version=SCHEMA_VERSION)
            self._connection.commit()
            if self._database_path is not None:
                self._verify_file_durability()
            else:
                self._verify_connection_setting("synchronous", 2)
                self._verify_connection_setting("wal_autocheckpoint", 1000)
        except BaseException as exc:
            cleanup_errors = self._rollback_for_error()
            self._invalidate_connection(exc, cleanup_errors)
            raise

    def _ensure_open(self) -> None:
        if self._state != _CONNECTION_OPEN:
            raise StorageError(
                f"Storage connection is {self._state.lower()} and cannot be used."
            )

    @staticmethod
    def _sqlite_primary_code(exc: sqlite3.Error) -> int | None:
        code = getattr(exc, "sqlite_errorcode", None)
        return code & 0xFF if isinstance(code, int) else None

    @staticmethod
    def _sqlite_error_description(exc: sqlite3.Error) -> str:
        code = getattr(exc, "sqlite_errorcode", None)
        name = getattr(exc, "sqlite_errorname", None)
        return f"{exc} [sqlite_errorcode={code!r}, sqlite_errorname={name!r}]"

    def _rollback_for_error(self) -> tuple[BaseException, ...]:
        try:
            active = self._connection.in_transaction
        except BaseException as state_error:
            return (state_error,)
        if not active:
            return ()
        try:
            self._connection.rollback()
        except BaseException as rollback_error:
            return (rollback_error,)
        try:
            still_active = self._connection.in_transaction
        except BaseException as state_error:
            return (state_error,)
        if still_active:
            return (
                StorageError(
                    "SQLite rollback returned but the transaction remains active."
                ),
            )
        return ()

    def _raise_with_cleanup_failure(
        self,
        message: str,
        cleanup_errors: tuple[BaseException, ...],
    ) -> StorageError:
        error = StorageError(message)
        for cleanup_error in cleanup_errors:
            description = (
                SQLiteStore._sqlite_error_description(cleanup_error)
                if isinstance(cleanup_error, sqlite3.Error)
                else f"{type(cleanup_error).__name__}: {cleanup_error}"
            )
            error.add_note(
                "Transaction cleanup also failed: " + description
            )
        return error

    def _ensure_events_table_exists(self) -> None:
        table = self._connection.execute(
            """
            SELECT name
            FROM sqlite_master
            WHERE type = 'table'
              AND name = 'system_events'
            """
        ).fetchone()

        if table is None:
            raise StorageError("The system_events table is missing.")

    def _install_append_only_triggers(self) -> None:
        self._connection.execute(
            f"""
            CREATE TRIGGER IF NOT EXISTS {_UPDATE_TRIGGER}
            BEFORE UPDATE ON system_events
            BEGIN
                SELECT RAISE(ABORT, 'system_events is append-only');
            END
            """
        )

        self._connection.execute(
            f"""
            CREATE TRIGGER IF NOT EXISTS {_DELETE_TRIGGER}
            BEFORE DELETE ON system_events
            BEGIN
                SELECT RAISE(ABORT, 'system_events is append-only');
            END
            """
        )

    def _install_idempotency_protection(self) -> None:
        self._connection.execute(_IDEMPOTENCY_INDEX_SQL)
        self._connection.execute(_IDEMPOTENCY_TRIGGER_SQL)

    def _verify_append_only_triggers(self) -> None:
        rows = self._connection.execute(
            """
            SELECT name, sql
            FROM sqlite_master
            WHERE type = 'trigger'
              AND tbl_name = 'system_events'
            """
        ).fetchall()

        installed = {
            row["name"]: row["sql"]
            for row in rows
        }

        expected = {
            _UPDATE_TRIGGER: """
                CREATE TRIGGER system_events_reject_update
                BEFORE UPDATE ON system_events
                BEGIN
                    SELECT RAISE(
                        ABORT,
                        'system_events is append-only'
                    );
                END
            """,
            _DELETE_TRIGGER: """
                CREATE TRIGGER system_events_reject_delete
                BEFORE DELETE ON system_events
                BEGIN
                    SELECT RAISE(
                        ABORT,
                        'system_events is append-only'
                    );
                END
            """,
        }
        if self._connection.execute(
            "PRAGMA user_version"
        ).fetchone()[0] in (_V3_SCHEMA_VERSION, SCHEMA_VERSION):
            expected[_IDEMPOTENCY_TRIGGER] = _IDEMPOTENCY_TRIGGER_SQL

        def normalize(sql: str) -> str:
            normalized = "".join(sql.lower().split()).rstrip(";")
            return normalized.replace(
                "createtriggerifnotexists",
                "createtrigger",
            )

        for name, expected_sql in expected.items():
            actual_sql = installed.get(name)

            if actual_sql is None:
                raise StorageError(
                    f"Required database trigger is missing: {name}"
                )

            if normalize(actual_sql) != normalize(expected_sql):
                raise StorageError(
                    f"Database trigger definition is invalid: {name}"
                )

        unexpected = set(installed) - set(expected)
        if unexpected:
            raise StorageError(
                "Unexpected triggers on system_events: "
                + ", ".join(sorted(unexpected))
            )

    @staticmethod
    def _normalize_sql(sql: str) -> str:
        return "".join(sql.lower().split()).rstrip(";")

    def _verify_schema(self, expected_version: int) -> None:
        """Verify the complete supported schema and database integrity."""

        version = self._connection.execute(
            "PRAGMA user_version"
        ).fetchone()[0]
        if version != expected_version:
            raise StorageError(
                f"Expected schema version {expected_version}, found {version}."
            )

        rows = self._connection.execute(
            """
            SELECT type, name, tbl_name, sql
            FROM sqlite_master
            WHERE name NOT LIKE 'sqlite_%'
            ORDER BY type, name
            """
        ).fetchall()
        objects = {(row["type"], row["name"]): row for row in rows}

        if expected_version == 1:
            expected_objects = {("table", "system_events")}
            expected_table_sql = _V1_TABLE_SQL
        elif expected_version == _V2_SCHEMA_VERSION:
            expected_objects = {
                ("table", "system_events"),
                ("trigger", _UPDATE_TRIGGER),
                ("trigger", _DELETE_TRIGGER),
            }
            expected_table_sql = _V2_TABLE_SQL
        elif expected_version in (_V3_SCHEMA_VERSION, SCHEMA_VERSION):
            expected_objects = {
                ("table", "system_events"),
                ("trigger", _UPDATE_TRIGGER),
                ("trigger", _DELETE_TRIGGER),
                ("trigger", _IDEMPOTENCY_TRIGGER),
                ("index", _IDEMPOTENCY_INDEX),
            }
            expected_table_sql = _V3_TABLE_SQL
        else:
            raise StorageError(f"Unsupported schema version {expected_version}.")

        actual_objects = set(objects)
        if actual_objects != expected_objects:
            missing = expected_objects - actual_objects
            unexpected = actual_objects - expected_objects
            details = []
            if missing:
                details.append(f"missing {sorted(missing)}")
            if unexpected:
                details.append(f"unexpected {sorted(unexpected)}")
            raise StorageError("Database schema objects are invalid: " + "; ".join(details))

        table = objects[("table", "system_events")]
        if self._normalize_sql(table["sql"]) != self._normalize_sql(
            expected_table_sql
        ):
            raise StorageError("The system_events table definition is invalid.")

        columns = self._connection.execute(
            "PRAGMA table_info(system_events)"
        ).fetchall()
        expected_columns = [
            ("event_id", "INTEGER", 0, 1),
            ("event_type", "TEXT", 1, 0),
            ("occurred_at_utc", "TEXT", 1, 0),
            ("payload_json", "TEXT", 1, 0),
        ]
        if expected_version in (_V3_SCHEMA_VERSION, SCHEMA_VERSION):
            expected_columns.append(("idempotency_key", "TEXT", 0, 0))
        actual_columns = [
            (row["name"], row["type"].upper(), row["notnull"], row["pk"])
            for row in columns
        ]
        if actual_columns != expected_columns:
            raise StorageError("The system_events columns are invalid.")

        indexes = self._connection.execute(
            """
            SELECT name, sql
            FROM sqlite_master
            WHERE type = 'index'
              AND tbl_name = 'system_events'
              AND name NOT LIKE 'sqlite_%'
            """
        ).fetchall()
        if expected_version in (_V3_SCHEMA_VERSION, SCHEMA_VERSION):
            if len(indexes) != 1 or indexes[0]["name"] != _IDEMPOTENCY_INDEX:
                raise StorageError("Database idempotency index is invalid.")
            if self._normalize_sql(indexes[0]["sql"]) != self._normalize_sql(
                _IDEMPOTENCY_INDEX_SQL
            ):
                raise StorageError("Database idempotency index definition is invalid.")
        elif indexes:
            raise StorageError("Unexpected indexes exist on system_events.")

        if expected_version in (
            _V2_SCHEMA_VERSION,
            _V3_SCHEMA_VERSION,
            SCHEMA_VERSION,
        ):
            self._verify_append_only_triggers()

        integrity = self._connection.execute(
            "PRAGMA integrity_check"
        ).fetchone()[0]
        if integrity != "ok":
            raise StorageError(f"SQLite integrity check failed: {integrity}")

    @staticmethod
    def _schema_transaction(connection: sqlite3.Connection) -> None:
        connection.execute("BEGIN IMMEDIATE")

    @staticmethod
    def _backup_manifest_path(backup_path: Path) -> Path:
        return backup_path.with_name(backup_path.name + ".manifest.json")

    @staticmethod
    def _assert_backup_sidecars(
        backup_path: Path,
        *,
        allow_wal_header: bool = False,
        inspect_shm: bool = True,
    ) -> None:
        """Reject WAL frames and SHM state outside the verifier's own handle."""

        wal_path = Path(str(backup_path) + "-wal")
        shm_path = Path(str(backup_path) + "-shm")
        try:
            if wal_path.exists():
                wal_size = wal_path.stat().st_size
                maximum_empty_size = 32 if allow_wal_header else 0
                if wal_size > maximum_empty_size:
                    raise StorageError(
                        "Backup has unexpected WAL sidecar content."
                    )
            if inspect_shm and shm_path.exists():
                raise StorageError(
                    "Backup has an unexpected SHM sidecar; another or stale "
                    "SQLite handle may exist."
                )
        except OSError as exc:
            raise StorageError("Could not inspect backup SQLite sidecars.") from exc

    @staticmethod
    def _write_manifest_file(path: Path, content: bytes, *, exclusive: bool) -> None:
        if exclusive:
            descriptor = os.open(
                path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600
            )
            with os.fdopen(descriptor, "wb") as manifest_file:
                manifest_file.write(content)
                manifest_file.flush()
                os.fsync(manifest_file.fileno())
            return

        temporary_path = path.with_name(path.name + f".tmp-{uuid4().hex}")
        descriptor = os.open(
            temporary_path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600
        )
        with os.fdopen(descriptor, "wb") as manifest_file:
            manifest_file.write(content)
            manifest_file.flush()
            os.fsync(manifest_file.fileno())
        os.replace(temporary_path, path)
        if os.name != "nt":
            directory_fd = os.open(path.parent, os.O_RDONLY)
            try:
                os.fsync(directory_fd)
            finally:
                os.close(directory_fd)

    @classmethod
    def _publish_backup_manifest(cls, path: Path, manifest: dict[str, Any], *, exclusive: bool = False) -> None:
        serialized = json.dumps(
            manifest, ensure_ascii=False, sort_keys=True, separators=(",", ":")
        ).encode("utf-8")
        cls._write_manifest_file(path, serialized, exclusive=exclusive)

    @classmethod
    def _verify_backup_manifest(cls, backup_path: str | Path) -> dict[str, Any]:
        """Validate the unsigned completion manifest and finalized-file digest."""

        path = Path(backup_path)
        manifest_path = cls._backup_manifest_path(path)
        try:
            manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
        except (OSError, UnicodeError, json.JSONDecodeError) as exc:
            raise StorageError("Backup manifest is missing or malformed.") from exc
        required = {
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
        if (
            not isinstance(manifest, dict)
            or not required.issubset(manifest)
            or manifest.get("manifest_format_version")
            != _BACKUP_MANIFEST_FORMAT_VERSION
            or manifest.get("status") != "VERIFIED"
            or manifest.get("checksum_scope") != _BACKUP_CHECKSUM_SCOPE
            or manifest.get("journal_mode") != "wal"
            or manifest.get("synchronous") != "FULL"
            or not isinstance(manifest.get("sha256"), str)
            or re.fullmatch(r"[0-9a-f]{64}", manifest["sha256"]) is None
        ):
            raise StorageError("Backup manifest is incomplete or invalid.")
        try:
            backup_id = str(manifest["backup_id"])
            migration_id = str(manifest["migration_attempt_id"])
            if (
                str(UUID(backup_id)) != backup_id
                or backup_id != migration_id
                or not Path(manifest["source_path"]).is_absolute()
                or isinstance(manifest["source_schema_version"], bool)
                or not isinstance(manifest["source_schema_version"], int)
                or manifest["source_schema_version"] not in (1, 2, 3, 4)
                or isinstance(manifest["event_count"], bool)
                or not isinstance(manifest["event_count"], int)
                or manifest["event_count"] < 0
                or (manifest["event_count"] == 0) != (manifest["highest_event_id"] is None)
                or (
                    manifest["highest_event_id"] is not None
                    and (
                        isinstance(manifest["highest_event_id"], bool)
                        or not isinstance(manifest["highest_event_id"], int)
                        or manifest["highest_event_id"] < 1
                    )
                )
                or (
                    manifest["sqlite_sequence"] is not None
                    and (
                        isinstance(manifest["sqlite_sequence"], bool)
                        or not isinstance(manifest["sqlite_sequence"], int)
                        or manifest["sqlite_sequence"] < 0
                    )
                )
                or (
                    manifest["sqlite_sequence"] is not None
                    and manifest["highest_event_id"] is not None
                    and manifest["sqlite_sequence"] < manifest["highest_event_id"]
                )
                or not isinstance(manifest["snapshot_utc"], str)
                or not isinstance(manifest["verification_utc"], str)
                or not manifest["snapshot_utc"].endswith("Z")
                or not manifest["verification_utc"].endswith("Z")
            ):
                raise ValueError("invalid manifest field")
            datetime.fromisoformat(manifest["snapshot_utc"].replace("Z", "+00:00"))
            datetime.fromisoformat(manifest["verification_utc"].replace("Z", "+00:00"))
        except (TypeError, ValueError, OSError) as exc:
            raise StorageError("Backup manifest contains invalid metadata.") from exc
        connection = None
        try:
            cls._assert_backup_sidecars(path)
            connection = cls._connect_existing(path)
            verifier = object.__new__(cls)
            verifier._connection = connection
            verifier._configure_connection()
            verifier._configure_durability()
            connection.execute("BEGIN IMMEDIATE")
            if not connection.in_transaction:
                raise StorageError(
                    "Could not reserve the backup while verifying its checksum."
                )
            cls._assert_backup_sidecars(
                path, allow_wal_header=True, inspect_shm=False
            )
            verifier._verify_file_durability()
            digest = cls._sha256_file(path)
            connection.rollback()
            if connection.in_transaction:
                raise StorageError(
                    "Backup checksum verification did not release its transaction."
                )
            connection.close()
            connection = None
            cls._assert_backup_sidecars(path)
        except BaseException as exc:
            if connection is not None:
                try:
                    if connection.in_transaction:
                        connection.rollback()
                    connection.close()
                except BaseException as close_error:
                    exc.add_note(
                        "Backup manifest verification cleanup failed: "
                        f"{type(close_error).__name__}: {close_error}"
                    )
            if not isinstance(exc, Exception):
                raise
            if isinstance(exc, StorageError):
                raise
            raise StorageError(
                "Could not safely verify the backup artifact and sidecars."
            ) from exc
        if digest != manifest["sha256"]:
            raise StorageError("Backup checksum does not match its manifest.")
        return manifest

    @staticmethod
    def _sha256_file(path: Path) -> str:
        digest = hashlib.sha256()
        with path.open("rb") as artifact:
            for block in iter(lambda: artifact.read(1024 * 1024), b""):
                digest.update(block)
        return digest.hexdigest()

    @staticmethod
    def _backup_watermark(connection: sqlite3.Connection, version: int) -> dict[str, Any]:
        row = connection.execute(
            "SELECT COUNT(*), MAX(event_id) FROM system_events"
        ).fetchone()
        sequence = None
        has_sequence = connection.execute(
            "SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = 'sqlite_sequence'"
        ).fetchone()
        if has_sequence:
            sequence_row = connection.execute(
                "SELECT seq FROM sqlite_sequence WHERE name = 'system_events'"
            ).fetchone()
            sequence = int(sequence_row[0]) if sequence_row else None
        return {
            "source_schema_version": version,
            "event_count": int(row[0]),
            "highest_event_id": int(row[1]) if row[1] is not None else None,
            "sqlite_sequence": sequence,
        }

    @staticmethod
    def _compare_backup_rows(
        source: sqlite3.Connection,
        backup: sqlite3.Connection,
        version: int,
        batch_size: int = 256,
    ) -> None:
        columns = ["event_id", "event_type", "occurred_at_utc", "payload_json"]
        if version in (_V3_SCHEMA_VERSION, SCHEMA_VERSION):
            columns.append("idempotency_key")
        selection = ", ".join(columns)
        source_cursor = source.execute(
            f"SELECT {selection} FROM system_events ORDER BY event_id"
        )
        backup_cursor = backup.execute(
            f"SELECT {selection} FROM system_events ORDER BY event_id"
        )
        while True:
            source_rows = source_cursor.fetchmany(batch_size)
            backup_rows = backup_cursor.fetchmany(batch_size)
            if [tuple(row) for row in source_rows] != [
                tuple(row) for row in backup_rows
            ]:
                raise StorageError("Backup event rows differ from the source snapshot.")
            if not source_rows:
                break

    @staticmethod
    def _run_online_backup(
        source: sqlite3.Connection, destination: sqlite3.Connection
    ) -> None:
        source.backup(destination)

    def _create_verified_backup(self, database_path: Path, version: int) -> Path:
        """Create a migration backup while holding the caller's write reservation."""

        self._ensure_open()
        self._require_migration_transaction()
        if self._database_path is None:
            raise StorageError("A file-backed store is required for migration backup.")
        try:
            source_path = Path(database_path).resolve(strict=True)
            owned_path = self._database_path.resolve(strict=True)
        except OSError as exc:
            raise StorageError("Could not resolve the migration source path.") from exc
        if source_path != owned_path:
            raise StorageError(
                "Migration backup source does not match the database reserved by this store."
            )

        attempt_id = str(uuid4())
        backup_path = database_path.with_name(
            f"{database_path.name}.v{version}-backup-{attempt_id.replace('-', '')}.sqlite3"
        )
        manifest_path = self._backup_manifest_path(backup_path)
        backup = None
        source = None
        verify = None
        manifest: dict[str, Any] | None = None
        owns_manifest = False
        try:
            source = self._connect_existing(source_path)
            source_store = object.__new__(SQLiteStore)
            source_store._connection = source
            source_store._configure_connection()
            source_store._configure_durability()
            source_store._verify_schema(expected_version=version)
            watermark = self._backup_watermark(source, version)
            watermark.update(
                {
                    "manifest_format_version": _BACKUP_MANIFEST_FORMAT_VERSION,
                    "status": "INCOMPLETE",
                    "backup_id": attempt_id,
                    "migration_attempt_id": attempt_id,
                    "source_path": str(source_path),
                    "snapshot_utc": datetime.now(timezone.utc)
                    .isoformat(timespec="microseconds")
                    .replace("+00:00", "Z"),
                    "journal_mode": "wal",
                    "synchronous": "FULL",
                    "verification_utc": None,
                    "sha256": None,
                    "checksum_scope": _BACKUP_CHECKSUM_SCOPE,
                }
            )
            manifest = watermark
            descriptor = os.open(
                backup_path, os.O_CREAT | os.O_EXCL | os.O_RDWR, 0o600
            )
            os.close(descriptor)
            self._publish_backup_manifest(manifest_path, manifest, exclusive=True)
            owns_manifest = True
            backup = self._connect_existing(backup_path)
            destination_store = object.__new__(SQLiteStore)
            destination_store._connection = backup
            destination_store._configure_connection()
            destination_store._configure_durability(allow_transition=True)
            self._run_online_backup(source, backup)
            backup.close()
            backup = None

            verify = self._connect_existing(backup_path)
            verifier = object.__new__(SQLiteStore)
            verifier._connection = verify
            verifier._configure_connection()
            verifier._configure_durability()
            verifier._verify_schema(expected_version=version)
            backup_watermark = self._backup_watermark(verify, version)
            for field in (
                "source_schema_version",
                "event_count",
                "highest_event_id",
                "sqlite_sequence",
            ):
                if backup_watermark[field] != watermark[field]:
                    raise StorageError(f"Backup watermark mismatch for {field}.")
            self._compare_backup_rows(source, verify, version)

            checkpoint = verify.execute(
                "PRAGMA wal_checkpoint(TRUNCATE)"
            ).fetchone()
            if (
                checkpoint is None
                or checkpoint[0] != 0
                or (
                    checkpoint[1] >= 0
                    and checkpoint[2] != checkpoint[1]
                )
            ):
                raise StorageError("Backup WAL checkpoint did not fully complete.")
            verifier._verify_schema(expected_version=version)
            verify.close()
            verify = None
            source.close()
            source = None

            self._assert_backup_sidecars(backup_path)
            manifest["status"] = "VERIFIED"
            manifest["verification_utc"] = (
                datetime.now(timezone.utc)
                .isoformat(timespec="microseconds")
                .replace("+00:00", "Z")
            )
            manifest["sha256"] = self._sha256_file(backup_path)
            self._publish_backup_manifest(manifest_path, manifest)
            # Reopen under a writer reservation so a replacement during
            # manifest publication is detected before returning the artifact.
            self._verify_backup_manifest(backup_path)
            return backup_path
        except BaseException as exc:
            for connection in (verify, backup, source):
                if connection is not None:
                    try:
                        connection.close()
                    except BaseException as close_error:
                        self._cleanup_errors.append(close_error)
                        exc.add_note(
                            "Backup connection cleanup also failed: "
                            f"{type(close_error).__name__}: {close_error}"
                        )
            if owns_manifest and manifest is not None and isinstance(exc, Exception):
                manifest["status"] = "REJECTED"
                manifest["verification_utc"] = (
                    datetime.now(timezone.utc)
                    .isoformat(timespec="microseconds")
                    .replace("+00:00", "Z")
                )
                manifest["sha256"] = None
                try:
                    self._publish_backup_manifest(manifest_path, manifest)
                except BaseException as manifest_error:
                    self._cleanup_errors.append(manifest_error)
                    exc.add_note(
                        "Could not publish REJECTED backup manifest: "
                        f"{type(manifest_error).__name__}: {manifest_error}"
                    )
            if not isinstance(exc, Exception):
                raise
            raise StorageError(
                f"Could not create and verify migration backup: {backup_path}"
            ) from exc

    def _create_verified_v1_backup(self, database_path: Path) -> Path:
        return self._create_verified_backup(database_path, version=1)

    def _require_migration_transaction(self) -> None:
        try:
            active = self._connection.in_transaction
        except BaseException as exc:
            raise StorageError("Could not verify the migration transaction.") from exc
        if not active or not self._migration_reservation_active:
            raise StorageError("Migration requires an active write transaction.")

    def _migrate_v1_to_v4(self, backup_path: Path) -> None:
        self._require_migration_transaction()
        self._verify_schema(expected_version=1)
        sequence_row = self._connection.execute(
            "SELECT seq FROM sqlite_sequence WHERE name = 'system_events'"
        ).fetchone()
        prior_sequence = int(sequence_row[0]) if sequence_row else None
        self._connection.execute(
            "ALTER TABLE system_events RENAME TO system_events_v1_migration"
        )
        self._connection.execute(_V2_TABLE_SQL)
        self._connection.execute(
            """
            INSERT INTO system_events (
                event_id, event_type, occurred_at_utc, payload_json
            )
            SELECT event_id, event_type, occurred_at_utc, payload_json
            FROM system_events_v1_migration
            """
        )
        self._connection.execute("DROP TABLE system_events_v1_migration")
        if prior_sequence is not None:
            sequence_update = self._connection.execute(
                "UPDATE sqlite_sequence SET seq = ? WHERE name = 'system_events'",
                (prior_sequence,),
            )
            if sequence_update.rowcount == 0:
                self._connection.execute(
                    "INSERT INTO sqlite_sequence (name, seq) VALUES (?, ?)",
                    ("system_events", prior_sequence),
                )
        self._install_append_only_triggers()
        self._connection.execute(
            "ALTER TABLE system_events ADD COLUMN idempotency_key TEXT"
        )
        self._install_idempotency_protection()
        self._connection.execute(f"PRAGMA user_version = {SCHEMA_VERSION}")

    def _migrate_v2_to_v4(self, backup_path: Path) -> None:
        self._require_migration_transaction()
        self._verify_schema(expected_version=_V2_SCHEMA_VERSION)
        self._connection.execute(
            "ALTER TABLE system_events ADD COLUMN idempotency_key TEXT"
        )
        self._install_idempotency_protection()
        self._connection.execute(f"PRAGMA user_version = {SCHEMA_VERSION}")

    def _migrate_v3_to_v4(self, backup_path: Path) -> None:
        self._require_migration_transaction()
        self._verify_schema(expected_version=_V3_SCHEMA_VERSION)
        self._connection.execute(f"PRAGMA user_version = {SCHEMA_VERSION}")

    def _initialize_schema(self) -> None:
        preliminary_version = self._connection.execute(
            "PRAGMA user_version"
        ).fetchone()[0]

        if preliminary_version > SCHEMA_VERSION:
            raise StorageError(
                f"Database schema version {preliminary_version} is newer "
                f"than supported version {SCHEMA_VERSION}."
            )

        if preliminary_version == 0:
            raise StorageError(
                "Database has no initialized schema; initialize it explicitly."
            )

        if preliminary_version == SCHEMA_VERSION:
            self._configure_durability()
            self._verify_schema(expected_version=SCHEMA_VERSION)
            return

        if preliminary_version not in (1, _V2_SCHEMA_VERSION, _V3_SCHEMA_VERSION):
            raise StorageError(f"Unsupported schema version {preliminary_version}.")

        if self._database_path is None:
            raise StorageError("A durable backup is required before migration.")

        # Reject malformed legacy databases before changing their journal mode.
        # A competing migration may commit between the version read and this
        # verification. In that case, defer authoritative validation until the
        # write reservation is acquired and the version is reread.
        try:
            self._verify_schema(expected_version=preliminary_version)
        except StorageError:
            observed_version = int(
                self._connection.execute("PRAGMA user_version").fetchone()[0]
            )
            if observed_version == preliminary_version or observed_version not in (
                1,
                _V2_SCHEMA_VERSION,
                _V3_SCHEMA_VERSION,
                SCHEMA_VERSION,
            ):
                raise
            preliminary_version = observed_version
        self._configure_durability(allow_transition=True)

        backup_path: Path | None = None
        phase = "BEGIN"
        try:
            self._schema_transaction(self._connection)
            self._migration_reservation_active = True
            phase = "LOCKED"
            self._require_migration_transaction()
            version = int(
                self._connection.execute("PRAGMA user_version").fetchone()[0]
            )
            if version == SCHEMA_VERSION:
                self._verify_file_durability()
                self._verify_schema(expected_version=SCHEMA_VERSION)
                phase = "COMMIT"
                self._connection.commit()
                self._migration_reservation_active = False
                return
            if version not in (1, _V2_SCHEMA_VERSION, _V3_SCHEMA_VERSION):
                raise StorageError(
                    f"Unsupported schema version {version} after reservation."
                )

            self._verify_schema(expected_version=version)
            backup_path = self._create_verified_backup(self._database_path, version)
            self._require_migration_transaction()
            if version == 1:
                self._migrate_v1_to_v4(backup_path)
            elif version == _V2_SCHEMA_VERSION:
                self._migrate_v2_to_v4(backup_path)
            else:
                self._migrate_v3_to_v4(backup_path)
            self._verify_schema(expected_version=SCHEMA_VERSION)
            phase = "COMMIT"
            self._connection.commit()
            self._migration_reservation_active = False
        except BaseException as exc:
            cleanup_errors = self._rollback_for_error()
            self._migration_reservation_active = False
            if cleanup_errors or phase == "COMMIT":
                self._invalidate_connection(exc, cleanup_errors)
            if not isinstance(exc, Exception):
                raise
            if phase == "COMMIT":
                message = (
                    "Migration COMMIT outcome is uncertain; the storage connection "
                    "was invalidated. Reopen and independently verify the database "
                    "before further use."
                )
            else:
                message = "Database migration failed; the source transaction was rolled back."
            if backup_path is not None:
                message += f" The verified backup was retained at {backup_path}."
            error = self._raise_with_cleanup_failure(message, cleanup_errors)
            raise error from exc

    def record_event(
        self,
        event_type: str,
        payload: Mapping[str, Any] | None,
        idempotency_key: str,
    ) -> int:
        """Append or identify an event using a stable producer-scoped key.

        Keys use lowercase ASCII ``producer-namespace:UUID`` form. The
        namespace starts with a letter and contains at most 48 lowercase
        letters, digits or hyphens. UUIDs use canonical lowercase text. The
        complete key is at most 85 characters. Keep the same key for retries.
        """

        self._ensure_open()

        if not isinstance(event_type, str) or not event_type.strip():
            raise ValueError("Event type cannot be empty.")

        if (
            not isinstance(idempotency_key, str)
            or len(idempotency_key) > 85
            or _IDEMPOTENCY_KEY_RE.fullmatch(idempotency_key) is None
        ):
            raise ValueError(
                "Idempotency key must use lowercase ASCII "
                "producer-namespace:UUID form."
            )
        namespace, identifier = idempotency_key.split(":", 1)
        if len(namespace) > 48 or str(UUID(identifier)) != identifier:
            raise ValueError("Idempotency key contains an invalid UUID.")

        if payload is None:
            event_payload = {}
        elif isinstance(payload, Mapping):
            event_payload = dict(payload)
        else:
            raise ValueError("Event payload must be a mapping.")

        if any(not isinstance(key, str) for key in event_payload):
            raise ValueError("Payload keys must be strings.")

        try:
            payload_json = json.dumps(
                event_payload,
                ensure_ascii=False,
                sort_keys=True,
                allow_nan=False,
            )
        except (TypeError, ValueError) as exc:
            raise ValueError(
                "Event payload must contain valid JSON data."
            ) from exc

        phase = "BEGIN"
        try:
            self._connection.execute("BEGIN IMMEDIATE")
            phase = "LOOKUP"
            existing = self._connection.execute(
                """
                SELECT event_id, event_type, payload_json
                FROM system_events
                WHERE idempotency_key = ?
                """,
                (idempotency_key,),
            ).fetchone()
            if existing is not None:
                if (
                    existing["event_type"] != event_type.strip()
                    or existing["payload_json"] != payload_json
                ):
                    raise IdempotencyConflictError(
                        "Idempotency key was already used for different event data."
                    )
                event_id = int(existing["event_id"])
                self._connection.rollback()
                return event_id

            timestamp = (
                datetime.now(timezone.utc)
                .isoformat(timespec="microseconds")
                .replace("+00:00", "Z")
            )
            phase = "INSERT"
            cursor = self._connection.execute(
                """
                INSERT INTO system_events (
                    event_type,
                    occurred_at_utc,
                    payload_json,
                    idempotency_key
                )
                VALUES (?, ?, ?, ?)
                """,
                (event_type.strip(), timestamp, payload_json, idempotency_key),
            )
            if cursor.rowcount != 1 or cursor.lastrowid is None:
                raise StorageError(
                    "Event insert did not insert exactly one row."
                )

            event_id = int(cursor.lastrowid)
            phase = "COMMIT"
            self._connection.commit()
            return event_id

        except BaseException as exc:
            if phase == "COMMIT" and not isinstance(exc, sqlite3.Error):
                cleanup_errors = self._rollback_for_error()
                self._invalidate_connection(exc, cleanup_errors)
                message = (
                    "Commit outcome is uncertain; the storage connection was "
                    "invalidated."
                )
                if isinstance(exc, Exception):
                    error = self._raise_with_cleanup_failure(
                        message, cleanup_errors
                    )
                    raise error from exc
                exc.add_note(message)
                raise

            if isinstance(exc, sqlite3.Error):
                code = self._sqlite_primary_code(exc)
                cleanup_errors = self._rollback_for_error()

                if phase == "COMMIT":
                    self._invalidate_connection(exc, cleanup_errors)
                    error = self._raise_with_cleanup_failure(
                        "Commit outcome is uncertain; the storage connection "
                        "was invalidated. " + self._sqlite_error_description(exc),
                        cleanup_errors,
                    )
                    raise error from exc

                if (
                    phase == "BEGIN"
                    and code == sqlite3.SQLITE_BUSY
                    and getattr(exc, "sqlite_errorcode", None) == sqlite3.SQLITE_BUSY
                ):
                    try:
                        transaction_active = self._connection.in_transaction
                    except BaseException as state_error:
                        cleanup_errors += (state_error,)
                        transaction_active = True
                    if not transaction_active and not cleanup_errors:
                        raise StorageError(
                            "Could not begin event transaction. "
                            + self._sqlite_error_description(exc)
                        ) from exc

                if (
                    phase == "INSERT"
                    and code == sqlite3.SQLITE_CONSTRAINT
                    and not cleanup_errors
                ):
                    raise StorageError(
                        "Event was rejected by a SQLite constraint. "
                        + self._sqlite_error_description(exc)
                    ) from exc

                self._invalidate_connection(exc, cleanup_errors)
                error = self._raise_with_cleanup_failure(
                    f"SQLite failure during event {phase.lower()}; "
                    "the storage connection was invalidated. "
                    + self._sqlite_error_description(exc),
                    cleanup_errors,
                )
                raise error from exc

            if isinstance(exc, IdempotencyConflictError):
                cleanup_errors = self._rollback_for_error()
                if not cleanup_errors:
                    return_error = exc
                else:
                    self._invalidate_connection(exc, cleanup_errors)
                    return_error = self._raise_with_cleanup_failure(
                        "Idempotency conflict occurred and transaction cleanup "
                        "failed; the storage connection was invalidated.",
                        cleanup_errors,
                    )
                    raise return_error from exc
                raise return_error

            if (
                isinstance(exc, StorageError)
                and phase == "INSERT"
                and str(exc) == "Event insert did not insert exactly one row."
            ):
                cleanup_errors = self._rollback_for_error()
                if not cleanup_errors:
                    raise
                self._invalidate_connection(exc, cleanup_errors)
                error = self._raise_with_cleanup_failure(
                    "Event insertion failed and transaction cleanup failed; "
                    "the storage connection was invalidated.",
                    cleanup_errors,
                )
                raise error from exc

            cleanup_errors = self._rollback_for_error()
            self._invalidate_connection(exc, cleanup_errors)
            if isinstance(exc, StorageError):
                raise
            raise

    def read_events(self, limit: int = 100) -> list[StoredEvent]:
        """Read events in chronological insertion order."""

        self._ensure_open()

        if type(limit) is not int or limit < 1:
            raise ValueError("Event limit must be a positive integer.")

        try:
            rows = self._connection.execute(
                """
                SELECT
                    event_id,
                    event_type,
                    occurred_at_utc,
                    payload_json,
                    idempotency_key
                FROM system_events
                ORDER BY event_id ASC
                LIMIT ?
                """,
                (limit,),
            ).fetchall()

            events = []
            for row in rows:
                payload = json.loads(row["payload_json"])
                if not isinstance(payload, dict):
                    raise ValueError("Stored event payload must be a JSON object.")
                events.append(
                    StoredEvent(
                        event_id=row["event_id"],
                        event_type=row["event_type"],
                        occurred_at_utc=row["occurred_at_utc"],
                        payload=payload,
                        idempotency_key=row["idempotency_key"],
                    )
                )
            return events

        except sqlite3.Error as exc:
            code = self._sqlite_primary_code(exc)
            try:
                transaction_active = self._connection.in_transaction
            except BaseException as state_error:
                transaction_active = True
                self._invalidate_connection(exc, (state_error,))

            if (
                code == sqlite3.SQLITE_BUSY
                and getattr(exc, "sqlite_errorcode", None) == sqlite3.SQLITE_BUSY
                and not transaction_active
            ):
                raise StorageError(
                    "Could not read stored events. "
                    + self._sqlite_error_description(exc)
                ) from exc

            self._invalidate_connection(exc)
            raise StorageError(
                "SQLite read failed; the storage connection was invalidated. "
                + self._sqlite_error_description(exc)
            ) from exc
        except (ValueError, TypeError, UnicodeDecodeError, RecursionError) as exc:
            self._invalidate_connection(exc)
            raise StorageError(
                "Stored event data is malformed; the storage connection was "
                "invalidated."
            ) from exc

    def close(self) -> None:
        """Close the database connection."""

        if (
            self._state == _CONNECTION_CLOSED
            and self._connection_close_succeeded
        ):
            return
        self._state = _CONNECTION_CLOSED
        close_error = self._attempt_connection_close()
        if close_error is not None:
            raise StorageError(
                "SQLite connection close failed; the store remains closed."
            ) from close_error

    def __enter__(self) -> "SQLiteStore":
        self._ensure_open()
        return self

    def __exit__(self, exc_type, exc_value, traceback) -> None:
        try:
            self.close()
        except BaseException as cleanup_error:
            if exc_value is None:
                raise
            exc_value.add_note(
                "SQLite context-manager cleanup also failed: "
                f"{type(cleanup_error).__name__}: {cleanup_error}"
            )
