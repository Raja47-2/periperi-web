# Periperi Extension Test Project

This folder contains deliberately mixed cryptography examples for testing the
Periperi VS Code extension. Do not reuse the weak examples in production.

## Expected detections

- `src/legacy_auth.py`: MD5, SHA-1, DES, ECB mode, and a hard-coded secret.
- `src/rsa_service.py`: RSA usage and a private-key marker with redacted evidence.
- `src/frontend_crypto.js`: SHA-1 and AES-ECB.
- `src/modern_crypto.py`: SHA-256 and AES-GCM examples for comparison.

## Test steps

1. Install **Periperi** from the [Visual Studio Marketplace](https://marketplace.visualstudio.com/items?itemName=TheSIxBugs.periperi) in VS Code.
2. Reload VS Code if requested.
3. Open this folder.
4. Open and save `src/legacy_auth.py`; findings should appear in **Problems**.
5. Open the Command Palette and run **Periperi: Scan Workspace**.
6. Run **Periperi: Show Report** to inspect all findings.
7. Run **Periperi: Export CBOM** to create a JSON report.

