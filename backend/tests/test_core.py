from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID
from datetime import datetime, timedelta, timezone

from app.detector import detect_file
from app.recommendations import recommendation
from app.risk import classical_risk, quantum_risk
from app.scanner import ScanOptions, scan_project


OPTIONS = ("pii", "standard_application", 15)


def detect(text: str):
    return detect_file(Path("example.py"), "example.py", text, *OPTIONS)


def test_detects_algorithms_and_libraries():
    findings = detect("import hashlib\nfrom Crypto.Cipher import AES\nhashlib.sha1(data)\nAES.new(key, AES.MODE_GCM)")
    names = {item["name"] for item in findings}
    assert {"SHA-1", "PyCryptodome", "AES-GCM"} <= names


def test_detects_requested_crypto_libraries():
    source = """
#include <openssl/evp.h>
from Crypto.Cipher import AES
from cryptography.hazmat.primitives import hashes
const crypto = require('crypto')
window.crypto.subtle.digest('SHA-256', data)
libsodium sodium_init crypto_secretbox
new BouncyCastleProvider()
PKCS#11 HSM
"""
    names = {item["name"] for item in detect(source)}
    assert {
        "OpenSSL", "PyCryptodome", "Python cryptography", "Node crypto",
        "Web Crypto API", "libsodium", "Bouncy Castle", "PKCS#11 / HSM",
    } <= names


def test_classical_risk_rules_are_explicit():
    assert classical_risk("MD5", "Algorithm")[0] == "high"
    assert classical_risk("AES-256-GCM", "Algorithm")[0] == "low"
    assert classical_risk("Private key detected", "Key")[0] == "critical"


def test_quantum_risk_uses_mosca_margin():
    result = quantum_risk("RSA-2048", "high_sensitivity", "complex_system", 15)
    assert result["margin"] == -12
    assert result["level"] == "critical"
    symmetric = quantum_risk("AES-256-GCM")
    assert symmetric["level"] == "not_applicable"


def test_recommendations_match_finding_type():
    assert "post-quantum" in recommendation("RSA-2048", "Algorithm", "medium")
    assert "rotate" in recommendation("Private key detected", "Key", "critical")


def test_private_key_is_reported_without_material():
    secret = "-----BEGIN PRIVATE KEY-----\nvery-sensitive-example-value\n-----END PRIVATE KEY-----"
    findings = detect(secret)
    key = next(item for item in findings if item["name"] == "Private key detected")
    assert key["evidence"] == "[key material redacted]"
    assert "very-sensitive" not in str(findings)


def test_sample_project_scans_end_to_end():
    root = Path(__file__).resolve().parents[2] / "samples" / "demo-project"
    result = scan_project(root, ScanOptions())
    assert result["files_scanned"] >= 6
    assert len(result["findings"]) >= 8
    assert any(item["category"] == "HSM" for item in result["findings"])
    assert any(item["category"] == "Certificate" for item in result["findings"])


def test_openssl_backend_parses_real_key_and_certificate(tmp_path):
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    (tmp_path / "server.key").write_bytes(key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    ))
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "ecdat.test")])
    now = datetime.now(timezone.utc)
    certificate = (
        x509.CertificateBuilder()
        .subject_name(name).issuer_name(name).public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now).not_valid_after(now + timedelta(days=30))
        .sign(key, hashes.SHA256())
    )
    (tmp_path / "server.crt").write_bytes(certificate.public_bytes(serialization.Encoding.PEM))
    result = scan_project(tmp_path, ScanOptions())
    names = {item["name"] for item in result["findings"]}
    assert {"Private key detected", "X.509 certificate", "RSA-2048"} <= names
    assert result["engines"]["openssl"]["version"].startswith("OpenSSL")


def test_binary_crypto_symbols_are_detected(tmp_path):
    (tmp_path / "crypto.dll").write_bytes(b"MZ\x00payload\x00EVP_sha1\x00EVP_aes_256_gcm\x00libcrypto-3")
    result = scan_project(tmp_path, ScanOptions())
    names = {item["name"] for item in result["findings"]}
    assert {"OpenSSL", "SHA-1", "AES-256-GCM"} <= names
