import hashlib
import hmac

from cryptography.hazmat.primitives.asymmetric import ec


def ecdh_shared_secret(private_key, peer_public_bytes):
    """Raw P-256 ECDH secret (the 32-byte X coordinate). WSM uses it directly as key material, no KDF.
    peer_public_bytes is the 65-byte uncompressed point."""
    peer = ec.EllipticCurvePublicKey.from_encoded_point(
        ec.SECP256R1(), peer_public_bytes
    )
    return private_key.exchange(ec.ECDH(), peer)


def derive_hmac_key(shared_secret, expanded_nonce, server_id, client_id):
    """SHA-256 over the shared secret, the expanded nonce, and both IDs. server_id and client_id are the bluetooth mac
    strings (ascii, 17 bytes, no terminator)."""
    return hashlib.sha256(
        shared_secret + expanded_nonce + server_id + client_id
    ).digest()


def client_hmac(key, challenge_nonce, response_nonce, server_id, client_id):
    """HMAC carried in the response (bytes 70:102). Field order must match libwsm."""
    data = challenge_nonce + response_nonce + server_id + client_id
    return hmac.new(key, data, hashlib.sha256).digest()


def server_hmac(key, response_nonce, challenge_nonce, client_id, server_id):
    """HMAC carried in the confirmation. Nonce order and ID order are both reversed vs. client_hmac, and key is derived
    from the response nonce (not the challenge). So a client HMAC can't be replayed as the confirmation."""
    data = response_nonce + challenge_nonce + client_id + server_id
    return hmac.new(key, data, hashlib.sha256).digest()
