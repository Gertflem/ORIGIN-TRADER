"""Structured JSON-lines logging for ORIGIN TRADER."""

import json
import logging
from collections.abc import Mapping
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


_LEVELS = {
    "DEBUG": logging.DEBUG,
    "INFO": logging.INFO,
    "WARNING": logging.WARNING,
    "ERROR": logging.ERROR,
    "CRITICAL": logging.CRITICAL,
}


class JsonLineFormatter(logging.Formatter):
    """Format each log record as one JSON object."""

    def format(self, record: logging.LogRecord) -> str:
        timestamp = (
            datetime.fromtimestamp(record.created, tz=timezone.utc)
            .isoformat(timespec="milliseconds")
            .replace("+00:00", "Z")
        )

        payload: dict[str, Any] = {
            "timestamp": timestamp,
            "level": record.levelname,
            "logger": record.name,
            "message": record.getMessage(),
        }

        event = getattr(record, "origin_event", None)
        if event is not None:
            payload["event"] = event

        context = getattr(record, "origin_context", None)
        if context:
            payload["context"] = context

        if record.exc_info:
            payload["exception"] = self.formatException(record.exc_info)

        return json.dumps(payload, ensure_ascii=False, sort_keys=True)


def configure_logging(
    level: str,
    log_path: str | Path = Path("logs/origin_trader.log"),
) -> logging.Logger:
    """Configure console and file logging."""

    if not isinstance(level, str):
        raise ValueError("Logging level must be text.")

    normalized_level = level.upper()

    if normalized_level not in _LEVELS:
        raise ValueError(f"Unsupported logging level: {level}")

    path = Path(log_path)

    if path.exists() and not path.is_file():
        raise ValueError("Log destination must be a file.")

    path.parent.mkdir(parents=True, exist_ok=True)

    file_handler = logging.FileHandler(path, encoding="utf-8")
    stream_handler = logging.StreamHandler()

    formatter = JsonLineFormatter()
    file_handler.setFormatter(formatter)
    stream_handler.setFormatter(formatter)

    logger = logging.getLogger("origin_trader")
    logger.setLevel(_LEVELS[normalized_level])
    logger.propagate = False

    # Prevent duplicate messages if logging is configured more than once.
    for handler in tuple(logger.handlers):
        logger.removeHandler(handler)
        handler.close()

    logger.addHandler(stream_handler)
    logger.addHandler(file_handler)

    return logger


def log_event(
    logger: logging.Logger,
    event: str,
    *,
    level: str = "INFO",
    context: Mapping[str, Any] | None = None,
) -> None:
    """Write a validated structured event."""

    if not isinstance(event, str) or not event.strip():
        raise ValueError("Event name cannot be empty.")

    if not isinstance(level, str) or level.upper() not in _LEVELS:
        raise ValueError(f"Unsupported logging level: {level}")

    event_context = dict(context or {})

    if any(not isinstance(key, str) for key in event_context):
        raise ValueError("Context keys must be text.")

    try:
        json.dumps(event_context, ensure_ascii=False, allow_nan=False)
    except (TypeError, ValueError) as exc:
        raise ValueError("Event context must contain JSON-safe values.") from exc

    logger.log(
        _LEVELS[level.upper()],
        event,
        extra={
            "origin_event": event,
            "origin_context": event_context,
        },
    )
