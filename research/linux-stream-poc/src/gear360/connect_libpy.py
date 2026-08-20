import os
import signal
import sys

from . import log
from .session import WsmAuthenticator, run_wifi_session


class PythonWsmAuthenticator(WsmAuthenticator):
    """WSM authentication via the pure-Python WSMClient from research/wsm-reveng."""

    def __init__(self, camera_mac: str, phone_mac: str) -> None:
        script_dir = os.path.dirname(os.path.abspath(__file__))
        sys.path.insert(
            0,
            os.path.join(script_dir, "..", "..", "..", "wsm-reveng", "src"),
        )
        from wsm import WSMClient

        self._client = WSMClient(camera_mac, phone_mac)

    def process_challenge(self, challenge: bytes) -> bytes | None:
        log.step("Running Python WSM client...")
        try:
            return self._client.process_challenge(challenge)
        except Exception as error:  # noqa: BLE001 (WSMClient surfaces crypto/parse failures opaquely)
            log.error(f"WSM challenge processing failed: {error}")
            return None

    def verify_confirm(self, confirm: bytes) -> bool:
        try:
            self._client.verify_confirm(confirm)
        except ValueError as error:
            log.error(f"WSM authentication failed: {error}")
            return False
        return True


def main() -> None:
    signal.signal(signal.SIGINT, signal.default_int_handler)
    try:
        run_wifi_session(PythonWsmAuthenticator)
    except KeyboardInterrupt:
        log.status("\nInterrupted")


if __name__ == "__main__":
    main()
