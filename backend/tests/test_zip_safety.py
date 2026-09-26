import io
import json
import tarfile
import zipfile

import pytest

from app.scanner import ScanError, ScanOptions, scan_upload, scan_zip


def make_zip(entries):
    stream = io.BytesIO()
    with zipfile.ZipFile(stream, "w") as archive:
        for name, content in entries.items():
            archive.writestr(name, content)
    return stream.getvalue()


def test_zip_project_scans():
    result = scan_zip(make_zip({"src/auth.py": "import hashlib\nhashlib.sha256(b'x')"}), "project.zip", ScanOptions())
    assert result["files_scanned"] == 1
    assert any(item["name"] == "SHA-256" for item in result["findings"])


def test_zip_path_traversal_is_rejected():
    with pytest.raises(ScanError, match="unsafe path"):
        scan_zip(make_zip({"../escape.py": "RSA"}), "bad.zip", ScanOptions())


def _tar(entries):
    stream = io.BytesIO()
    with tarfile.open(fileobj=stream, mode="w") as archive:
        for name, content in entries.items():
            payload = content if isinstance(content, bytes) else content.encode()
            info = tarfile.TarInfo(name)
            info.size = len(payload)
            archive.addfile(info, io.BytesIO(payload))
    return stream.getvalue()


def test_container_archive_expands_layers_and_scans_binaries(monkeypatch):
    layer = _tar({"usr/lib/libcrypto.so": b"\x7fELF\x00OpenSSL\x00EVP_sha1"})
    manifest = json.dumps([{"Config": "config.json", "RepoTags": ["demo:latest"], "Layers": ["layer.tar"]}])
    image = _tar({"manifest.json": manifest, "config.json": "{}", "layer.tar": layer})
    monkeypatch.setattr("app.scanner.scan_container_with_tools", lambda *_: ([], {
        "syft": {"available": True, "scan": "completed"},
        "trivy": {"available": True, "scan": "completed"},
    }))
    result = scan_upload(image, "demo-image.tar", ScanOptions())
    assert result["input_type"] == "container-image"
    assert result["container_layers_scanned"] == 1
    assert {"OpenSSL", "SHA-1"} <= {item["name"] for item in result["findings"]}
