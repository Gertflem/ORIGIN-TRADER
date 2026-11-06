import json
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory

from origin_trader.core.logging import (
    configure_logging,
    log_event,
)


def close_test_logger(logger):
    """Close and remove handlers before temporary files are deleted."""
    for handler in tuple(logger.handlers):
        logger.removeHandler(handler)
        handler.flush()
        handler.close()


class LoggingTests(unittest.TestCase):

    def test_structured_event_is_written_to_file(self):
        with TemporaryDirectory() as directory:
            log_path = Path(directory) / "test.log"
            logger = configure_logging("INFO", log_path)

            try:
                log_event(
                    logger,
                    "startup_completed",
                    context={"mode": "OBSERVE"},
                )

                for handler in logger.handlers:
                    handler.flush()

                lines = log_path.read_text(
                    encoding="utf-8"
                ).splitlines()

                self.assertEqual(len(lines), 1)

                record = json.loads(lines[0])

                self.assertEqual(
                    record["event"], "startup_completed"
                )
                self.assertEqual(record["level"], "INFO")
                self.assertEqual(
                    record["context"]["mode"], "OBSERVE"
                )
                self.assertTrue(
                    record["timestamp"].endswith("Z")
                )
            finally:
                close_test_logger(logger)

    def test_invalid_logging_level_is_rejected(self):
        with TemporaryDirectory() as directory:
            log_path = Path(directory) / "test.log"

            with self.assertRaises(ValueError):
                configure_logging("INVALID", log_path)

    def test_reconfiguration_does_not_duplicate_handlers(self):
        with TemporaryDirectory() as directory:
            log_path = Path(directory) / "test.log"
            logger = configure_logging("INFO", log_path)

            try:
                configure_logging("INFO", log_path)

                self.assertEqual(len(logger.handlers), 2)

                log_event(logger, "single_event")

                for handler in logger.handlers:
                    handler.flush()

                lines = log_path.read_text(
                    encoding="utf-8"
                ).splitlines()

                self.assertEqual(len(lines), 1)
            finally:
                close_test_logger(logger)

    def test_non_json_context_is_rejected(self):
        with TemporaryDirectory() as directory:
            logger = configure_logging(
                "INFO",
                Path(directory) / "test.log",
            )

            try:
                with self.assertRaises(ValueError):
                    log_event(
                        logger,
                        "invalid_event",
                        context={"object": object()},
                    )
            finally:
                close_test_logger(logger)


if __name__ == "__main__":
    unittest.main()
