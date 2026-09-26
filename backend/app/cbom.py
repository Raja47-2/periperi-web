"""CBOM-style report generation from a completed scan."""

from __future__ import annotations

from collections import Counter
from datetime import datetime, timezone
from typing import Any


def build_summary(findings: list[dict[str, Any]], files_scanned: int, files_skipped: int = 0) -> dict[str, Any]:
    risks = Counter(item["risk"] for item in findings)
    quantum = Counter(item["quantum_risk"] for item in findings)
    categories = Counter(item["category"].lower() for item in findings)
    return {
        "files_scanned": files_scanned,
        "files_skipped": files_skipped,
        "findings": len(findings),
        "critical": risks["critical"],
        "high": risks["high"],
        "medium": risks["medium"],
        "low": risks["low"],
        "info": risks["info"],
        "risk_distribution": dict(risks),
        "quantum_distribution": dict(quantum),
        "category_distribution": dict(categories),
    }


def build_cbom(scan: dict[str, Any]) -> dict[str, Any]:
    findings = scan["findings"]
    by_category: dict[str, list[str]] = {}
    for category in ("Algorithm", "Library", "Certificate", "Key", "HSM"):
        by_category[category.lower() + "s"] = sorted({
            item["name"] for item in findings if item["category"] == category
        })
    return {
        "specification": "ECDAT CBOM Prototype 1.0",
        "disclaimer": "Rule-based prototype inventory; validate findings before security decisions.",
        "scan_id": scan["id"],
        "project_name": scan["project_name"],
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "scan_created_at": scan["created_at"],
        "summary": scan["summary"],
        "assumptions": scan["assumptions"],
        "input_type": scan.get("input_type", "project-directory"),
        "engines": scan.get("engines", {}),
        "inventory": by_category,
        "findings": findings,
    }
