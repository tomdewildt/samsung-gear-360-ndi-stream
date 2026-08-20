import contextlib
import os
import select
import signal
import subprocess
import time

from . import log
from .session import WsmAuthenticator, run_wifi_session

RESPONSE_SIZE = 102


class HelperWsmAuthenticator(WsmAuthenticator):
    """WSM authentication via the ARM wsm_helper binary, run under qemu-arm-static."""

    def __init__(
        self, camera_mac: str, phone_mac: str, lib_dir: str, helper_path: str
    ) -> None:
        self._camera_mac = camera_mac
        self._phone_mac = phone_mac
        self._lib_dir = lib_dir
        self._helper_path = helper_path
        self._process: subprocess.Popen[bytes] | None = None

    def process_challenge(self, challenge: bytes) -> bytes | None:
        log.step("Running wsm_helper...")
        self._process = subprocess.Popen(
            [
                "qemu-arm-static",
                "-E",
                f"LD_LIBRARY_PATH={self._lib_dir}",
                self._helper_path,
                "full_auth",
                self._camera_mac,
                self._phone_mac,
            ],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        if self._process.stdin is None or self._process.stdout is None:
            return None
        self._process.stdin.write(challenge)
        self._process.stdin.flush()

        stdout_fd = self._process.stdout.fileno()
        response = b""
        deadline = time.monotonic() + 15.0
        while len(response) < RESPONSE_SIZE:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                log.error("Timed out waiting for wsm_helper response")
                break
            ready, _, _ = select.select([stdout_fd], [], [], min(remaining, 1.0))
            if ready:
                chunk = os.read(stdout_fd, RESPONSE_SIZE - len(response))
                if not chunk:
                    break
                response += chunk

        if len(response) != RESPONSE_SIZE:
            log.error(f"Expected {RESPONSE_SIZE}-byte response, got {len(response)}")
            self.close()
            return None
        return response

    def verify_confirm(self, confirm: bytes) -> bool:
        if self._process is None or self._process.stdin is None:
            return False
        with contextlib.suppress(BrokenPipeError):
            self._process.stdin.write(confirm)
            self._process.stdin.flush()
            self._process.stdin.close()
        try:
            self._process.wait(timeout=10)
        except subprocess.TimeoutExpired:
            self._process.kill()
            self._process.wait()
        if self._process.returncode != 0:
            log.error("WSM authentication failed")
            return False
        return True

    def close(self) -> None:
        if self._process is not None and self._process.poll() is None:
            with contextlib.suppress(OSError):
                self._process.kill()


def main() -> None:
    script_dir = os.path.dirname(os.path.abspath(__file__))
    lib_dir = os.path.join(
        script_dir,
        "..",
        "..",
        "..",
        "apk-reveng",
        "sources",
        "samsung-accessory-service",
        "resources",
        "lib",
        "armeabi",
    )
    helper_path = os.path.join(
        script_dir, "..", "..", "..", "libwsm-reveng", "target", "wsm_helper"
    )
    if not os.path.exists(helper_path):
        log.error(
            f"{helper_path} not found. "
            "Compile it first (run 'make build/binary' in ../../../libwsm-reveng)."
        )
        return

    signal.signal(signal.SIGINT, signal.default_int_handler)
    try:
        run_wifi_session(
            lambda camera_mac, phone_mac: HelperWsmAuthenticator(
                camera_mac, phone_mac, lib_dir, helper_path
            )
        )
    except KeyboardInterrupt:
        log.status("\nInterrupted")


if __name__ == "__main__":
    main()
