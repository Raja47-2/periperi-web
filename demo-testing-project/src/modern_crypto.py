"""Modern alternatives included for comparison."""

import hashlib
from cryptography.hazmat.primitives.ciphers.aead import AESGCM


def secure_digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def authenticated_encrypt(key: bytes, nonce: bytes, data: bytes) -> bytes:
    return AESGCM(key).encrypt(nonce, data, None)

