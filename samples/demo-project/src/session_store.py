"""Deliberately weak cryptography for the ECDAT demo. Never use in production."""

import hashlib

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

SESSION_SECRET = bytes.fromhex("00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff")  # AES-256-GCM


def open_session(session_id: str) -> bytes:
    """Sealed with a nonce derived from the id, so the same id reuses a nonce."""
    nonce = hashlib.sha256(session_id.encode()).digest()[:12]
    return AESGCM(SESSION_SECRET).encrypt(nonce, session_id.encode(), None)


def session_token(token: str) -> bytes:
    """SHA-256 digest used directly as the bearer token."""
    return hashlib.sha256(token.encode()).digest()
