"""Validated, read-only application configuration."""

from dataclasses import dataclass
from enum import Enum
from pathlib import Path
import tomllib
from typing import Any


class ConfigError(ValueError):
    """Raised when application configuration is invalid."""


class OperatingMode(str, Enum):
    OBSERVE = "OBSERVE"


@dataclass(frozen=True, slots=True)
class AppConfig:
    app_name: str
    operating_mode: OperatingMode
    log_level: str
    database_path: Path

    def __post_init__(self) -> None:
        if not self.app_name.strip():
            raise ConfigError("Application name cannot be empty.")

        if self.operating_mode is not OperatingMode.OBSERVE:
            raise ConfigError("Only OBSERVE mode is currently permitted.")

        if self.log_level not in {
            "DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"
        }:
            raise ConfigError("Invalid logging level.")

        if not isinstance(self.database_path, Path):
            raise ConfigError("Database path must be a Path.")


def _section(
    raw: dict[str, Any],
    name: str,
    expected_keys: set[str],
) -> dict[str, Any]:
    value = raw.get(name)

    if not isinstance(value, dict):
        raise ConfigError(f"Missing or invalid configuration section: {name}")

    actual_keys = set(value)
    if actual_keys != expected_keys:
        missing = expected_keys - actual_keys
        unknown = actual_keys - expected_keys
        raise ConfigError(
            f"Invalid keys in section '{name}'. "
            f"Missing: {sorted(missing)}; unknown: {sorted(unknown)}"
        )

    return value


def load_config(
    path: str | Path = Path("config/default.toml"),
) -> AppConfig:
    """Load and validate application configuration from TOML."""

    config_path = Path(path)

    try:
        with config_path.open("rb") as config_file:
            raw = tomllib.load(config_file)
    except (OSError, tomllib.TOMLDecodeError) as exc:
        raise ConfigError(
            f"Could not load configuration: {config_path}"
        ) from exc

    expected_sections = {"application", "logging", "storage"}
    if set(raw) != expected_sections:
        raise ConfigError("Configuration contains missing or unknown sections.")

    application = _section(
        raw, "application", {"name", "mode"}
    )
    logging = _section(
        raw, "logging", {"level"}
    )
    storage = _section(
        raw, "storage", {"database"}
    )

    if not isinstance(application["name"], str):
        raise ConfigError("Application name must be text.")

    if not isinstance(application["mode"], str):
        raise ConfigError("Operating mode must be text.")

    if not isinstance(logging["level"], str):
        raise ConfigError("Logging level must be text.")

    if not isinstance(storage["database"], str):
        raise ConfigError("Database path must be text.")

    try:
        mode = OperatingMode(application["mode"])
    except ValueError as exc:
        raise ConfigError(
            f"Unsupported operating mode: {application['mode']}"
        ) from exc

    return AppConfig(
        app_name=application["name"],
        operating_mode=mode,
        log_level=logging["level"],
        database_path=Path(storage["database"]),
    )
