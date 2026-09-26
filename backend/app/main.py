"""FastAPI entry point for the ECDAT prototype."""

from __future__ import annotations

import uuid
from contextlib import asynccontextmanager
from datetime import datetime, timezone
from pathlib import Path

from fastapi import FastAPI, File, Form, HTTPException, UploadFile
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

from .cbom import build_cbom, build_summary
from .container_tools import container_tool_details
from .openssl_inspector import openssl_details
from .scanner import ScanError, ScanOptions, scan_project, scan_upload
from .storage import get_scan, initialize, list_scans, save_scan


ROOT = Path(__file__).resolve().parents[2]
SAMPLE_PROJECT = ROOT / "samples" / "demo-project"


@asynccontextmanager
async def lifespan(_: FastAPI):
    initialize()
    yield


app = FastAPI(title="ECDAT API", version="1.0.0", lifespan=lifespan)
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:5173", "http://127.0.0.1:5173"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


def _options(sensitivity: str, migration_complexity: str, threat_timeline: int) -> ScanOptions:
    if sensitivity not in {"ephemeral", "internal", "pii", "financial", "high_sensitivity"}:
        raise HTTPException(422, "Unsupported data sensitivity value.")
    if migration_complexity not in {"small_project", "standard_application", "legacy_application", "complex_system"}:
        raise HTTPException(422, "Unsupported migration complexity value.")
    if not 5 <= threat_timeline <= 50:
        raise HTTPException(422, "Threat timeline must be between 5 and 50 years.")
    return ScanOptions(sensitivity, migration_complexity, threat_timeline)


def _complete_scan(result: dict) -> dict:
    result["id"] = str(uuid.uuid4())
    result["created_at"] = datetime.now(timezone.utc).isoformat()
    result["summary"] = build_summary(result["findings"], result["files_scanned"], result["files_skipped"])
    save_scan(result)
    return result


@app.exception_handler(ScanError)
async def scan_error_handler(_, exc: ScanError):
    return JSONResponse(status_code=400, content={"detail": str(exc)})


@app.get("/api/health")
def health() -> dict:
    return {"status": "ok", "service": "ecdat", "engines": {"openssl": openssl_details(), **container_tool_details()}}


@app.get("/api/scans")
def scans() -> list[dict]:
    return list_scans()


@app.post("/api/scan")
async def create_scan(
    file: UploadFile = File(...),
    sensitivity: str = Form("pii"),
    migration_complexity: str = Form("standard_application"),
    threat_timeline: int = Form(15),
) -> dict:
    if not file.filename:
        raise HTTPException(400, "Choose a repository archive, container archive, binary, certificate or key.")
    upload = await file.read()
    return _complete_scan(scan_upload(upload, file.filename, _options(sensitivity, migration_complexity, threat_timeline)))


@app.post("/api/scan/sample")
def create_sample_scan(
    sensitivity: str = "pii",
    migration_complexity: str = "standard_application",
    threat_timeline: int = 15,
) -> dict:
    return _complete_scan(scan_project(SAMPLE_PROJECT, _options(sensitivity, migration_complexity, threat_timeline)))


@app.get("/api/scan/{scan_id}")
def scan_detail(scan_id: str) -> dict:
    scan = get_scan(scan_id)
    if not scan:
        raise HTTPException(404, "Scan not found.")
    return scan


@app.get("/api/scan/{scan_id}/report")
def scan_report(scan_id: str) -> dict:
    scan = get_scan(scan_id)
    if not scan:
        raise HTTPException(404, "Scan not found.")
    return build_cbom(scan)
