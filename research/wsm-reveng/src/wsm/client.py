import hmac
import os

from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from .crypto import client_hmac, derive_hmac_key, ecdh_shared_secret, server_hmac
from .nonce_table import expand_nonce


class WSMClient:
    def __init__(self, server_id, client_id):
        self.server_id = server_id.encode() if isinstance(server_id, str) else server_id
        self.client_id = client_id.encode() if isinstance(client_id, str) else client_id
        self._private_key = ec.generate_private_key(ec.SECP256R1())
        self._public_bytes = self._private_key.public_key().public_bytes(
            Encoding.X962,
            PublicFormat.UncompressedPoint,
        )
        self._hmac_key_server = None
        self._challenge_nonce = None
        self._response_nonce = None

    def process_challenge(self, challenge):
        """Process a 70-byte challenge and return the 102-byte response."""
        if len(challenge) != 70:
            raise ValueError(f"Challenge must be 70 bytes, got {len(challenge)}")
        if challenge[0] != 0 or challenge[1] != 0 or challenge[2] != 70:
            raise ValueError("Invalid challenge header")

        server_pubkey = challenge[3:68]
        self._challenge_nonce = challenge[68:70]
        self._response_nonce = os.urandom(2)

        shared_secret = ecdh_shared_secret(self._private_key, server_pubkey)

        key_client = derive_hmac_key(
            shared_secret,
            expand_nonce(self._challenge_nonce),
            self.server_id,
            self.client_id,
        )
        self._hmac_key_server = derive_hmac_key(
            shared_secret,
            expand_nonce(self._response_nonce),
            self.server_id,
            self.client_id,
        )

        mac = client_hmac(
            key_client,
            self._challenge_nonce,
            self._response_nonce,
            self.server_id,
            self.client_id,
        )

        response = bytearray(102)
        response[0] = 0  # version
        response[1] = 1  # message type
        response[2] = 102  # total length
        response[3:68] = self._public_bytes
        response[68:70] = self._response_nonce
        response[70:102] = mac
        return bytes(response)

    def verify_confirm(self, confirm):
        """Verify a 35-byte confirmation from the camera. Raises on failure."""
        if len(confirm) != 35:
            raise ValueError(f"Confirm must be 35 bytes, got {len(confirm)}")
        if confirm[0] != 0 or confirm[1] != 2 or confirm[2] != 35:
            raise ValueError("Invalid confirm header")
        if self._hmac_key_server is None:
            raise RuntimeError("Must call process_challenge before verify_confirm")

        expected = server_hmac(
            self._hmac_key_server,
            self._response_nonce,
            self._challenge_nonce,
            self.client_id,
            self.server_id,
        )
        if not hmac.compare_digest(confirm[3:35], expected):
            raise ValueError("Server HMAC verification failed")
