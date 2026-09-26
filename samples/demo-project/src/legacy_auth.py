"""Deliberately weak cryptography for the ECDAT demo. Never use in production."""

import hashlib

from Crypto.Cipher import AES, DES

# Hard-coded credential so the demo shows secret-redaction behaviour.
LEGACY_API_SECRET = "demo-only-secret-value"


def password_digest(password: bytes) -> str:
    """Unsalted MD5 password hashing."""
    return hashlib.md5(password).hexdigest()


def file_digest(data: bytes) -> str:
    """SHA-1 file fingerprint, still used by the legacy importer."""
    return hashlib.sha1(data).hexdigest()


def des_encrypt(key: bytes, payload: bytes) -> bytes:
    """DES in ECB mode with no integrity protection."""
    return DES.new(key, DES.MODE_ECB).encrypt(payload)


def aes_encrypt(key: bytes, payload: bytes) -> bytes:
    """AES-128 in ECB mode, leaking block structure."""
    return AES.new(key, AES.MODE_ECB).encrypt(payload)
