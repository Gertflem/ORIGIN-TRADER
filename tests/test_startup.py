import unittest
from contextlib import redirect_stdout
from io import StringIO

from origin_trader import __version__
from origin_trader.cli import main


class StartupTests(unittest.TestCase):

    def test_version(self):
        self.assertEqual(__version__, "0.1.0")

    def test_application_starts_in_observe_mode(self):
        output = StringIO()

        with redirect_stdout(output):
            result = main()

        self.assertEqual(result, 0)

        startup_message = output.getvalue()

        self.assertIn("OBSERVE (read-only)", startup_message)
        self.assertIn("NOT CONNECTED", startup_message)
        self.assertIn("Order execution: DISABLED", startup_message)


if __name__ == "__main__":
    unittest.main()