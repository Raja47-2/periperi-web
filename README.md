# ECDAT

ECDAT is an Enterprise Cryptographic Discovery and Assessment Tool for SIH26164. It scans source repositories, binaries, container-image archives and cryptographic artifacts to find algorithms, keys, certificates, libraries and HSM references. It assesses classical and quantum risk, recommends safer or post-quantum alternatives, and exports a JSON CBOM.

## Features

- Safe ZIP/TAR repository and Docker/OCI image-archive scanning
- OpenSSL-backed X.509, public-key, private-key and PKCS#12 inspection
- Binary symbol and embedded-string fingerprinting without executing binaries
- Syft cryptographic-package inventory and Trivy vulnerability analysis for containers
- Secret-redacted cryptographic discovery across common source and config files
- Detection for OpenSSL, PyCryptodome, Python cryptography, Node Crypto, Web Crypto, libsodium, Bouncy Castle and PKCS#11/HSM
- Deterministic classical and quantum-risk rules
- Searchable dashboard, finding details and real scan summaries
- SQLite scan history and JSON CBOM export
- Local VS Code extension with save-time diagnostics, full-engine workspace/artifact scanning, engine visibility and CBOM export

## Run

Backend:

```powershell
python -m venv .venv
.venv\Scripts\Activate.ps1
pip install -r requirements.txt
uvicorn app.main:app --reload --app-dir backend
```

Frontend, in a second terminal:

```powershell
cd frontend
npm install
npm run dev
```

Open `http://localhost:5173`.

VS Code extension:

```powershell
cd vscode-extension
npm install
npm run compile
```

Open `vscode-extension` in VS Code and press `F5` to launch the Extension Development Host.

## Demo

Choose **run the built-in demo**, or upload a repository ZIP/TAR, Docker/OCI image archive, binary, certificate or key. Open any finding to inspect safe evidence and recommendations, then export the CBOM. The health endpoint reports the exact OpenSSL backend and whether Syft and Trivy are available.

For complete container analysis, install `syft` and `trivy` on the backend host. ECDAT still safely extracts and scans image layers when either CLI is unavailable, and records each engine's status in the scan result.
