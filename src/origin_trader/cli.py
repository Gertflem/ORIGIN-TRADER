"""Command-line entry point for ORIGIN TRADER."""

from . import __version__


def main() -> int:
    print()
    print(f"ORIGIN TRADER v{__version__}")
    print("=" * 36)
    print("Operating mode : OBSERVE (read-only)")
    print("Market data    : NOT CONNECTED")
    print("Order execution: DISABLED")
    print("System status  : INITIAL STARTUP CHECK")
    print()
    return 0
