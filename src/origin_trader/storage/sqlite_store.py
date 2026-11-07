"""SQLite persistence engine for ORIGIN TRADER."""

from collections.abc import Mapping
from dataclasses import dataclass
from datetime import datetime, timezone
import json
from pathlib import Path
import sqlite3
from typing import Any
from uuid import uuid4


SCHEMA_VERSION = 2

_UPDATE_TRIGGER = "system_events_reject_update"
_DELETE_TRIGGER = "system_events_reject_delete"
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


class StorageError(RuntimeError):
    """Raised when persistent storage cannot operate safely."""


@dataclass(frozen=True, slots=True)
class StoredEvent:
    event_id: int
    event_type: str
    occurred_at_utc: str
    payload: dict[str, Any]


class SQLiteStore:
    """SQLite storage service with protected append-only events."""

    def __init__(self, database_path: str | Path):
        raw_path = str(database_path)

        if not raw_path.strip():
            raise ValueError("Database path cannot be empty.")

        if raw_path != ":memory:":
            Path(raw_path).parent.mkdir(parents=True, exist_ok=True)
            self._database_path = Path(raw_path).resolve()
        else:
            self._database_path = None

        self._closed = False

        try:
            # Explicit autocommit keeps transaction boundaries under this
            # class's control, including DDL and PRAGMA user_version changes.
            self._connection = sqlite3.connect(
                raw_path,
                timeout=5.0,
                isolation_level=None,
            )
            self._connection.row_factory = sqlite3.Row
            self._connection.execute("PRAGMA foreign_keys = ON")
            self._connection.execute("PRAGMA busy_timeout = 5000")
            self._connection.execute("PRAGMA recursive_triggers = ON")
            recursive_triggers = self._connection.execute(
                "PRAGMA recursive_triggers"
            ).fetchone()[0]
            if recursive_triggers != 1:
                raise StorageError(
                    "SQLite recursive triggers could not be enabled."
                )
            self._initialize_schema()

        except Exception:
            connection = getattr(self, "_connection", None)
            if connection is not None:
                connection.close()
            self._closed = True
            raise

    def _ensure_open(self) -> None:
        if self._closed:
            raise StorageError("Storage connection is closed.")

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
        elif expected_version == SCHEMA_VERSION:
            expected_objects = {
                ("table", "system_events"),
                ("trigger", _UPDATE_TRIGGER),
                ("trigger", _DELETE_TRIGGER),
            }
            expected_table_sql = _V2_TABLE_SQL
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
        actual_columns = [
            (row["name"], row["type"].upper(), row["notnull"], row["pk"])
            for row in columns
        ]
        if actual_columns != expected_columns:
            raise StorageError("The system_events columns are invalid.")

        # There are no user-defined indexes in either supported schema.
        indexes = self._connection.execute(
            """
            SELECT name
            FROM sqlite_master
            WHERE type = 'index'
              AND tbl_name = 'system_events'
              AND name NOT LIKE 'sqlite_%'
            """
        ).fetchall()
        if indexes:
            raise StorageError("Unexpected indexes exist on system_events.")

        if expected_version == SCHEMA_VERSION:
            self._verify_append_only_triggers()

        integrity = self._connection.execute(
            "PRAGMA integrity_check"
        ).fetchone()[0]
        if integrity != "ok":
            raise StorageError(f"SQLite integrity check failed: {integrity}")

    @staticmethod
    def _schema_transaction(connection: sqlite3.Connection) -> None:
        connection.execute("BEGIN IMMEDIATE")

    def _create_verified_v1_backup(self, database_path: Path) -> Path:
        """Create and validate a consistent, retained pre-migration backup."""

        backup_path = database_path.with_name(
            f"{database_path.name}.v1-backup-{uuid4().hex}.sqlite3"
        )
        backup = None
        try:
            backup = sqlite3.connect(
                str(backup_path), timeout=5.0, isolation_level=None
            )
            self._connection.backup(backup)
            backup.close()
            backup = None

            verify = sqlite3.connect(
                str(backup_path), timeout=5.0, isolation_level=None
            )
            try:
                verify.row_factory = sqlite3.Row
                verifier = object.__new__(SQLiteStore)
                verifier._connection = verify
                verifier._verify_schema(expected_version=1)
            finally:
                verify.close()
        except Exception as exc:
            if backup is not None:
                backup.close()
            # Keep any incomplete artifact for diagnosis; it is never treated
            # as a verified backup. SQLite backup is consistent, but this
            # local backup is not protected from a privileged local attacker.
            raise StorageError(
                f"Could not create and verify migration backup: {backup_path}"
            ) from exc
        return backup_path

    def _migrate_v1_to_v2(self) -> None:
        if not hasattr(self, "_database_path") or self._database_path is None:
            raise StorageError(
                "A durable backup is required before migrating this database."
            )

        backup_path = self._create_verified_v1_backup(self._database_path)
        try:
            self._schema_transaction(self._connection)
            self._verify_schema(expected_version=1)
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
            self._install_append_only_triggers()
            self._connection.execute(
                f"PRAGMA user_version = {SCHEMA_VERSION}"
            )
            self._verify_schema(expected_version=SCHEMA_VERSION)
            self._connection.commit()
        except Exception as exc:
            if self._connection.in_transaction:
                self._connection.rollback()
            raise StorageError(
                "Database migration failed; the original database was rolled "
                f"back and the verified backup was retained at {backup_path}."
            ) from exc

    def _initialize_schema(self) -> None:
        version = self._connection.execute(
            "PRAGMA user_version"
        ).fetchone()[0]

        if version > SCHEMA_VERSION:
            raise StorageError(
                f"Database schema version {version} is newer "
                f"than supported version {SCHEMA_VERSION}."
            )

        if version == 0:
            existing_tables = self._connection.execute(
                """
                SELECT name
                FROM sqlite_master
                WHERE type = 'table'
                  AND name NOT LIKE 'sqlite_%'
                """
            ).fetchall()

            if existing_tables:
                raise StorageError(
                    "Unversioned database contains existing tables."
                )

            try:
                self._schema_transaction(self._connection)
                self._connection.execute(_V2_TABLE_SQL)
                self._install_append_only_triggers()
                self._connection.execute(
                    f"PRAGMA user_version = {SCHEMA_VERSION}"
                )
                self._verify_schema(expected_version=SCHEMA_VERSION)
                self._connection.commit()
            except Exception:
                if self._connection.in_transaction:
                    self._connection.rollback()
                raise

        elif version == 1:
            self._migrate_v1_to_v2()

        else:
            self._verify_schema(expected_version=SCHEMA_VERSION)

    def record_event(
        self,
        event_type: str,
        payload: Mapping[str, Any] | None = None,
    ) -> int:
        """Append one event and return its database ID."""

        self._ensure_open()

        if not isinstance(event_type, str) or not event_type.strip():
            raise ValueError("Event type cannot be empty.")

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

        timestamp = (
            datetime.now(timezone.utc)
            .isoformat(timespec="microseconds")
            .replace("+00:00", "Z")
        )

        try:
            self._connection.execute("BEGIN IMMEDIATE")
            cursor = self._connection.execute(
                """
                INSERT INTO system_events (
                    event_type,
                    occurred_at_utc,
                    payload_json
                )
                VALUES (?, ?, ?)
                """,
                (event_type.strip(), timestamp, payload_json),
            )
            if cursor.rowcount != 1 or cursor.lastrowid is None:
                raise StorageError(
                    "Event insert did not insert exactly one row."
                )

            event_id = int(cursor.lastrowid)
            self._connection.commit()
            return event_id

        except (sqlite3.Error, StorageError) as exc:
            if self._connection.in_transaction:
                self._connection.rollback()
            if isinstance(exc, StorageError):
                raise
            raise StorageError("Could not record system event.") from exc

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
                    payload_json
                FROM system_events
                ORDER BY event_id ASC
                LIMIT ?
                """,
                (limit,),
            ).fetchall()

            return [
                StoredEvent(
                    event_id=row["event_id"],
                    event_type=row["event_type"],
                    occurred_at_utc=row["occurred_at_utc"],
                    payload=json.loads(row["payload_json"]),
                )
                for row in rows
            ]

        except (sqlite3.Error, json.JSONDecodeError) as exc:
            raise StorageError("Could not read stored events.") from exc

    def close(self) -> None:
        """Close the database connection."""

        if not self._closed:
            self._connection.close()
            self._closed = True

    def __enter__(self) -> "SQLiteStore":
        self._ensure_open()
        return self

    def __exit__(self, exc_type, exc_value, traceback) -> None:
        self.close()
