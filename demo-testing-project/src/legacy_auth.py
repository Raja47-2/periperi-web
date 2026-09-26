"""Deliberately weak examples for local ECDAT testing only."""

import hashlib
from Crypto.Cipher import AES, DES

API_SECRET = "demo-hard-coded-secret"


def old_password_digest(password: bytes) -> str:
    return hashlib.md5(password).hexdigest()


def old_file_digest(data: bytes) -> str:
    return hashlib.sha1(data).hexdigest()


def legacy_encrypt(key: bytes, payload: bytes) -> bytes:
    cipher = DES.new(key, DES.MODE_ECB)
    return cipher.encrypt(payload)


def aes_ecb_encrypt(key: bytes, payload: bytes) -> bytes:
    cipher = AES.new(key, AES.MODE_ECB)
    return cipher.encrypt(payload)

