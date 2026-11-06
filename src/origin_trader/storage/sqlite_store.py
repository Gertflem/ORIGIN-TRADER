"""SQLite persistence engine for ORIGIN TRADER."""

from collections.abc import Mapping
from dataclasses import dataclass
from datetime import datetime, timezone
import json
from pathlib import Path
import sqlite3
from typing import Any


SCHEMA_VERSION = 1


class StorageError(RuntimeError):
    """Raised when persistent storage cannot operate safely."""


@dataclass(frozen=True, slots=True)
class StoredEvent:
    event_id: int
    event_type: str
    occurred_at_utc: str
    payload: dict[str, Any]


class SQLiteStore:
    """Small, explicit SQLite storage service."""

    def __init__(self, database_path: str | Path):
        raw_path = str(database_path)

        if not raw_path.strip():
            raise ValueError("Database path cannot be empty.")

        if raw_path != ":memory:":
            path = Path(raw_path)
            path.parent.mkdir(parents=True, exist_ok=True)

        self._closed = False

        try:
            self._connection = sqlite3.connect(
                raw_path,
                timeout=5.0,
            )
            self._connection.row_factory = sqlite3.Row
            self._connection.execute("PRAGMA foreign_keys = ON")
            self._connection.execute("PRAGMA busy_timeout = 5000")

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

            with self._connection:
                self._connection.execute(
                    """
                    CREATE TABLE system_events (
                        event_id INTEGER PRIMARY KEY AUTOINCREMENT,
                        event_type TEXT NOT NULL
                            CHECK(length(trim(event_type)) > 0),
                        occurred_at_utc TEXT NOT NULL,
                        payload_json TEXT NOT NULL
                    )
                    """
                )

                self._connection.execute(
                    f"PRAGMA user_version = {SCHEMA_VERSION}"
                )

        else:
            table = self._connection.execute(
                """
                SELECT name
                FROM sqlite_master
                WHERE type = 'table'
                  AND name = 'system_events'
                """
            ).fetchone()

            if table is None:
                raise StorageError(
                    "Database schema is marked as current, "
                    "but the system_events table is missing."
                )

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
            with self._connection:
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

                return int(cursor.lastrowid)

        except sqlite3.Error as exc:
            raise StorageError("Could not record system event.") from exc

    def read_events(self, limit: int = 100) -> list[StoredEvent]:
        """Read stored events in chronological insertion order."""

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