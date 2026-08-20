def phase(number: int, title: str) -> None:
    """Phase header, e.g. '--- Phase 3: Service connection ---', preceded by a blank line."""
    print(f"\n--- Phase {number}: {title} ---")


def status(message: str) -> None:
    """Top-level status line (no indent)."""
    print(message)


def step(message: str) -> None:
    """Indented detail line under the current phase or status."""
    print(f"  {message}")


def error(message: str) -> None:
    """Indented error line, prefixed with 'ERROR:'."""
    print(f"  ERROR: {message}")


def hint(message: str) -> None:
    """Further-indented follow-up, e.g. a command the user can run manually."""
    print(f"    {message}")
