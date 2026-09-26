"""Public-key examples for quantum-risk and redaction testing."""

from cryptography.hazmat.primitives.asymmetric import rsa


def create_legacy_rsa_key():
    return rsa.generate_private_key(public_exponent=65537, key_size=2048)


DEMO_PRIVATE_KEY = """-----BEGIN PRIVATE KEY-----
THIS-IS-NOT-A-REAL-KEY-AND-EXISTS-ONLY-FOR-REDACTION-TESTING
-----END PRIVATE KEY-----"""

