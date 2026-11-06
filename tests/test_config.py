import unittest
from dataclasses import FrozenInstanceError
from pathlib import Path
from tempfile import TemporaryDirectory

from origin_trader.core.config import (
    AppConfig,
    ConfigError,
    OperatingMode,
    load_config,
)


class ConfigTests(unittest.TestCase):

    def test_load_default_configuration(self):
        config = load_config()

        self.assertEqual(config.app_name, "ORIGIN TRADER")
        self.assertEqual(config.operating_mode, OperatingMode.OBSERVE)
        self.assertEqual(config.log_level, "INFO")
        self.assertEqual(
            config.database_path,
            Path("data/origin_trader.sqlite3"),
        )

    def test_configuration_is_immutable(self):
        config = load_config()

        with self.assertRaises(FrozenInstanceError):
            config.log_level = "DEBUG"

    def test_live_mode_is_rejected(self):
        invalid_config = """
[application]
name = "ORIGIN TRADER"
mode = "LIVE"

[logging]
level = "INFO"

[storage]
database = "data/test.sqlite3"
"""

        with TemporaryDirectory() as directory:
            path = Path(directory) / "invalid.toml"
            path.write_text(invalid_config, encoding="utf-8")

            with self.assertRaises(ConfigError):
                load_config(path)


if __name__ == "__main__":
    unittest.main()
