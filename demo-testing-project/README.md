# ECDAT Extension Test Project

This folder contains deliberately mixed cryptography examples for testing the
ECDAT VS Code extension. Do not reuse the weak examples in production.

## Expected detections

- `src/legacy_auth.py`: MD5, SHA-1, DES, ECB mode, and a hard-coded secret.
- `src/rsa_service.py`: RSA usage and a private-key marker with redacted evidence.
- `src/frontend_crypto.js`: SHA-1 and AES-ECB.
- `src/modern_crypto.py`: SHA-256 and AES-GCM examples for comparison.

## Test steps

1. Install `ECDAT-Cryptographic-Scanner-0.1.0.vsix` in VS Code.
2. Reload VS Code if requested.
3. Open this folder.
4. Open and save `src/legacy_auth.py`; findings should appear in **Problems**.
5. Open the Command Palette and run **ECDAT: Scan Workspace**.
6. Run **ECDAT: Show Report** to inspect all findings.
7. Run **ECDAT: Export CBOM** to create a JSON report.

