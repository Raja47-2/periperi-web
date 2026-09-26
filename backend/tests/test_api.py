from fastapi.testclient import TestClient

from app.main import app


def test_health_and_sample_scan():
    with TestClient(app) as client:
        assert client.get("/api/health").json()["status"] == "ok"
        response = client.post("/api/scan/sample")
        assert response.status_code == 200
        scan = response.json()
        assert scan["summary"]["findings"] == len(scan["findings"])
        report = client.get(f"/api/scan/{scan['id']}/report")
        assert report.status_code == 200
        assert report.json()["project_name"] == "demo-project"


def test_invalid_upload_has_useful_error():
    with TestClient(app) as client:
        response = client.post(
            "/api/scan",
            files={"file": ("project.zip", b"not a zip", "application/zip")},
        )
    assert response.status_code == 400
    assert "valid ZIP" in response.json()["detail"]


def test_health_reports_openssl_and_container_engines():
    with TestClient(app) as client:
        engines = client.get("/api/health").json()["engines"]
    assert engines["openssl"]["version"].startswith("OpenSSL")
    assert "syft" in engines and "trivy" in engines
