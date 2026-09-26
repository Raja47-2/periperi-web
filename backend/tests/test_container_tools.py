from app.container_tools import findings_from_syft, findings_from_trivy
from app.scanner import ScanOptions


def test_syft_crypto_packages_become_findings():
    payload = {"artifacts": [
        {"name": "openssl", "version": "3.5.0"},
        {"name": "libsodium23", "version": "1.0.20"},
        {"name": "unrelated", "version": "1"},
    ]}
    names = {item["name"] for item in findings_from_syft(payload, ScanOptions())}
    assert names == {"OpenSSL", "libsodium"}


def test_trivy_crypto_vulnerability_keeps_severity():
    payload = {"Results": [{"Vulnerabilities": [{
        "VulnerabilityID": "CVE-DEMO-1",
        "PkgName": "openssl",
        "InstalledVersion": "3.0.0",
        "Severity": "HIGH",
    }]}]}
    findings = findings_from_trivy(payload, ScanOptions())
    assert len(findings) == 1
    assert findings[0]["risk"] == "high"
    assert "CVE-DEMO-1" in findings[0]["evidence"]
