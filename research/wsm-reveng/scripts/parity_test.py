import argparse
import hmac as hmac_mod
import os
import subprocess
import sys

from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
from wsm.client import WSMClient
from wsm.crypto import client_hmac, derive_hmac_key, ecdh_shared_secret
from wsm.nonce_table import expand_nonce

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
RESEARCH_DIR = os.path.dirname(os.path.dirname(SCRIPT_DIR))

WSM_HELPER_BIN = os.path.join(RESEARCH_DIR, "libwsm-reveng", "target", "wsm_helper")
LIB_DIR = os.path.realpath(
    os.path.join(
        RESEARCH_DIR,
        "apk-reveng",
        "sources",
        "samsung-accessory-service",
        "resources",
        "lib",
        "armeabi",
    )
)

SERVER_ID = "C8:38:70:3F:97:75"
CLIENT_ID = "A8:3B:76:BA:B2:FE"


def header(text: str) -> None:
    """Banner line, e.g. '=== WSM Parity Test ===', preceded by a blank line."""
    print(f"\n=== {text} ===")


def section(label: str) -> None:
    """Numbered section marker, e.g. '[1] ...', preceded by a blank line."""
    print(f"\n{label}")


def status(message: str) -> None:
    """Top-level status line (no indent)."""
    print(message)


def step(message: str) -> None:
    """Indented detail line under the current section."""
    print(f"  {message}")


def detail(message: str) -> None:
    """Further-indented sub-detail."""
    print(f"    {message}")


def error(message: str) -> None:
    """Indented error line, prefixed with 'ERROR:'."""
    print(f"  ERROR: {message}")


def run_wsm_helper(challenge_70b: bytes) -> bytes:
    """Run the arm wsm_helper via qemu: 70-byte challenge in, 102-byte response out."""
    result = subprocess.run(
        [
            "qemu-arm-static",
            "-E",
            f"LD_LIBRARY_PATH={LIB_DIR}",
            WSM_HELPER_BIN,
            "challenge",
            SERVER_ID,
            CLIENT_ID,
        ],
        input=challenge_70b,
        capture_output=True,
        timeout=10,
        check=False,
    )
    if result.returncode != 0:
        raise RuntimeError(
            f"wsm_helper failed (exit {result.returncode}):\n{result.stderr.decode(errors='replace')}"
        )

    return result.stdout


def make_challenge(server_private_key: ec.EllipticCurvePrivateKey) -> bytes:
    """Build a 70-byte challenge packet from a known server keypair."""
    pubkey_bytes = server_private_key.public_key().public_bytes(
        Encoding.X962,
        PublicFormat.UncompressedPoint,
    )
    nonce = os.urandom(2)
    challenge = bytearray(70)
    challenge[0] = 0
    challenge[1] = 0
    challenge[2] = 70
    challenge[3:68] = pubkey_bytes
    challenge[68:70] = nonce
    return bytes(challenge)


def verify_response_hmac(
    server_private_key: ec.EllipticCurvePrivateKey, challenge: bytes, response: bytes
) -> bool:
    """Recompute the response HMAC from the known server private key and compare."""
    client_pubkey = response[3:68]
    challenge_nonce = challenge[68:70]
    response_nonce = response[68:70]
    received = response[70:102]

    shared = ecdh_shared_secret(server_private_key, client_pubkey)
    key = derive_hmac_key(
        shared,
        expand_nonce(challenge_nonce),
        SERVER_ID.encode(),
        CLIENT_ID.encode(),
    )
    expected = client_hmac(
        key,
        challenge_nonce,
        response_nonce,
        SERVER_ID.encode(),
        CLIENT_ID.encode(),
    )

    return hmac_mod.compare_digest(received, expected)


def test_nonce_expansion() -> None:
    step("Nonce table: embedded, 256 entries x 8 bytes")
    for byte in [0, 1, 127, 255]:
        detail(
            f"expand({byte:3d}, 0) first 8B = {expand_nonce(bytes([byte, 0]))[:8].hex()}"
        )
    step("OK")


def run_single_test() -> bool:
    server_key = ec.generate_private_key(ec.SECP256R1())
    challenge = make_challenge(server_key)
    step(f"Challenge nonce: {challenge[68:70].hex()}")

    binary_response = run_wsm_helper(challenge)
    if len(binary_response) != 102:
        error(f"wsm_helper returned {len(binary_response)} bytes, expected 102")
        return False
    if not verify_response_hmac(server_key, challenge, binary_response):
        error("binary response HMAC invalid")
        return False
    step(f"Binary  HMAC valid (nonce {binary_response[68:70].hex()})")

    python_response = WSMClient(SERVER_ID, CLIENT_ID).process_challenge(challenge)
    if not verify_response_hmac(server_key, challenge, python_response):
        error("python response HMAC invalid")
        return False
    step(f"Python  HMAC valid (nonce {python_response[68:70].hex()})")
    return True


def main() -> None:
    parser = argparse.ArgumentParser(
        description="WSM parity test: Python vs ARM binary"
    )
    parser.add_argument(
        "--runs",
        type=int,
        default=5,
        help="Number of test runs (default: 5)",
    )
    args = parser.parse_args()

    if not os.path.exists(WSM_HELPER_BIN):
        error(f"wsm_helper not found at {WSM_HELPER_BIN}")
        step("Build it first: `make build/binary` in ../libwsm-reveng")
        sys.exit(1)

    header("WSM Parity Test")
    status(f"Server ID: {SERVER_ID}  Client ID: {CLIENT_ID}")
    section("[1] Nonce expansion table check")
    test_nonce_expansion()

    passed = 0
    for i in range(args.runs):
        section(f"[{i + 2}] Auth round {i + 1}/{args.runs}")
        try:
            if run_single_test():
                passed += 1
                step("PASS")
        except Exception as e:  # noqa: BLE001 - report and continue
            error(str(e))

    header(f"Results: {passed}/{args.runs} passed")
    sys.exit(0 if passed == args.runs else 1)


if __name__ == "__main__":
    main()
