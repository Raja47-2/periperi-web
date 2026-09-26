# demo-project

A deliberately weak sample application used by the ECDAT web demo. It exists so the
dashboard always has realistic findings to display. **Do not reuse any of this code
in production.**

## Expected detections

| File | Expected findings |
| --- | --- |
| `src/legacy_auth.py` | MD5, SHA-1, DES, AES in ECB mode, hard-coded secret |
| `src/payment_service.java` | RSA-1024, DES, Bouncy Castle, PKCS#11 / HSM |
| `src/hsm_client.go` | PKCS#11 / HSM, ECDSA, SHA-256 |
| `src/frontend_crypto.js` | SHA-1, AES-128-ECB, Node crypto, Web Crypto API |
| `certs/server.crt` | X.509 certificate plus its RSA-2048 public key |
| `certs/server.key` | RSA-2048 private key (OpenSSL-validated, material redacted) |
| `config/app.conf` | OpenSSL, Diffie-Hellman, ChaCha20 |

The pair in `certs/` is a real, self-signed 2048-bit RSA key pair generated purely for
this demo. It protects nothing and must never be reused.
