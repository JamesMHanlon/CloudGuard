"""
FastAPI backend for the cloud compliance automation system.
"""

import json
import os
from pathlib import Path
from contextlib import asynccontextmanager
from typing import Optional

from dotenv import load_dotenv
from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse
from pydantic import BaseModel

load_dotenv()

from backend.compliance.scanner import scan_all, ScanResult
from backend.ml.model import load_or_train, predict_risk, feature_importances
from backend.rag.explainer import explain_violation, explain_resource_summary
from backend.rag.knowledge_base import get_knowledge_base
from backend.paths import DATA_DIR, FRONTEND_DIR

DATA_PATH = DATA_DIR / "mock_configs" / "resources.json"
FRONTEND_PATH = FRONTEND_DIR

_resources: list[dict] = []
_scan_results: list[ScanResult] = []
_ml_pipeline = None


@asynccontextmanager
async def lifespan(app: FastAPI):
    global _resources, _scan_results, _ml_pipeline

    print("[Startup] Loading resources...")
    with open(DATA_PATH) as f:
        _resources = json.load(f)["resources"]

    print("[Startup] Running compliance scan...")
    _scan_results = scan_all(_resources)

    print("[Startup] Loading/training ML model...")
    _ml_pipeline = load_or_train()

    print("[Startup] Scoring resources with ML model...")
    resource_map = {r["resource_id"]: r for r in _resources}
    for scan in _scan_results:
        res = resource_map[scan.resource_id]
        scan.risk_score = predict_risk(_ml_pipeline, res["config"])

    print(f"[Startup] Ready — {len(_resources)} resources, {sum(1 for s in _scan_results if not s.compliant)} non-compliant")
    yield


app = FastAPI(title="Cloud Compliance Automation", version="1.0.0", lifespan=lifespan)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)


def _scan_to_dict(scan: ScanResult, include_violations: bool = True) -> dict:
    d = {
        "resource_id": scan.resource_id,
        "resource_name": scan.resource_name,
        "cloud": scan.cloud,
        "service": scan.service,
        "region": scan.region,
        "compliant": scan.compliant,
        "risk_score": round(scan.risk_score, 3),
        "violation_count": len(scan.violations),
    }
    if include_violations:
        d["violations"] = [
            {
                "rule_id": v.rule_id,
                "framework": v.framework,
                "control": v.control,
                "severity": v.severity,
                "title": v.title,
                "detail": v.detail,
                "field": v.field,
                "actual_value": str(v.actual_value),
                "expected_value": str(v.expected_value),
                "doc_id": v.doc_id,
            }
            for v in scan.violations
        ]
    return d


# ---------------------------------------------------------------------------
# API routes
# ---------------------------------------------------------------------------

@app.get("/api/summary")
def get_summary():
    total = len(_scan_results)
    non_compliant = sum(1 for s in _scan_results if not s.compliant)
    critical = sum(
        1 for s in _scan_results
        for v in s.violations if v.severity == "CRITICAL"
    )
    high = sum(
        1 for s in _scan_results
        for v in s.violations if v.severity == "HIGH"
    )
    avg_risk = sum(s.risk_score for s in _scan_results) / total if total else 0

    clouds = {}
    for s in _scan_results:
        if s.cloud not in clouds:
            clouds[s.cloud] = {"total": 0, "non_compliant": 0}
        clouds[s.cloud]["total"] += 1
        if not s.compliant:
            clouds[s.cloud]["non_compliant"] += 1

    frameworks = {}
    for s in _scan_results:
        for v in s.violations:
            fw = v.framework
            if fw not in frameworks:
                frameworks[fw] = 0
            frameworks[fw] += 1

    return {
        "total_resources": total,
        "compliant": total - non_compliant,
        "non_compliant": non_compliant,
        "compliance_rate": round((total - non_compliant) / total * 100, 1) if total else 0,
        "critical_violations": critical,
        "high_violations": high,
        "avg_risk_score": round(avg_risk, 3),
        "by_cloud": clouds,
        "violations_by_framework": frameworks,
    }


@app.get("/api/resources")
def list_resources(
    cloud: Optional[str] = None,
    service: Optional[str] = None,
    compliant: Optional[bool] = None,
    min_risk: Optional[float] = None,
):
    results = _scan_results
    if cloud:
        results = [s for s in results if s.cloud.lower() == cloud.lower()]
    if service:
        results = [s for s in results if s.service.lower() == service.lower()]
    if compliant is not None:
        results = [s for s in results if s.compliant == compliant]
    if min_risk is not None:
        results = [s for s in results if s.risk_score >= min_risk]

    results = sorted(results, key=lambda s: s.risk_score, reverse=True)
    return [_scan_to_dict(s, include_violations=False) for s in results]


@app.get("/api/resources/{resource_id}")
def get_resource(resource_id: str):
    scan = next((s for s in _scan_results if s.resource_id == resource_id), None)
    if not scan:
        raise HTTPException(404, "Resource not found")
    resource = next((r for r in _resources if r["resource_id"] == resource_id), None)
    result = _scan_to_dict(scan)
    result["config"] = resource.get("config", {})
    result["tags"] = resource.get("tags", {})
    return result


@app.post("/api/resources/{resource_id}/explain")
def explain_resource(resource_id: str):
    scan = next((s for s in _scan_results if s.resource_id == resource_id), None)
    if not scan:
        raise HTTPException(404, "Resource not found")
    resource = next((r for r in _resources if r["resource_id"] == resource_id), None)

    api_key = os.environ.get("ANTHROPIC_API_KEY")
    if not api_key:
        raise HTTPException(503, "ANTHROPIC_API_KEY not configured — RAG explanations unavailable")

    summary = explain_resource_summary(scan, resource)
    violation_explanations = []
    for v in scan.violations[:5]:  # limit to 5 to avoid long waits
        exp = explain_violation(v, resource)
        violation_explanations.append({
            "rule_id": v.rule_id,
            "title": v.title,
            "severity": v.severity,
            "explanation": exp,
        })

    return {
        "resource_id": resource_id,
        "summary": summary,
        "violation_explanations": violation_explanations,
    }


@app.get("/api/ml/importances")
def get_feature_importances():
    return feature_importances(_ml_pipeline)


@app.post("/api/scan/custom")
def scan_custom(body: dict):
    """Scan an ad-hoc resource config submitted by the user."""
    required = ["cloud", "service", "name", "config"]
    for field in required:
        if field not in body:
            raise HTTPException(400, f"Missing field: {field}")

    resource = {
        "resource_id": "custom-scan",
        "name": body["name"],
        "cloud": body["cloud"],
        "service": body["service"],
        "region": body.get("region", "custom"),
        "tags": body.get("tags", {}),
        "config": body["config"],
    }

    from backend.compliance.scanner import scan_resource
    scan = scan_resource(resource)
    scan.risk_score = predict_risk(_ml_pipeline, resource["config"])

    result = _scan_to_dict(scan)

    if os.environ.get("ANTHROPIC_API_KEY") and scan.violations:
        result["summary"] = explain_resource_summary(scan, resource)
    else:
        result["summary"] = None

    return result


# ---------------------------------------------------------------------------
# Auto-detect cloud + service from config field fingerprints
# ---------------------------------------------------------------------------

_FIELD_HINTS: list[tuple[set, str, str]] = [
    # AWS
    ({"bucket_acl", "public_access_block"},               "AWS", "S3"),
    ({"ssh_unrestricted", "imdsv2", "ebs_encrypted"},      "AWS", "EC2"),
    ({"root_mfa", "root_access_keys", "mfa_enforced"},     "AWS", "IAM"),
    ({"multi_region", "log_validation", "include_global_events"}, "AWS", "CloudTrail"),
    ({"publicly_accessible", "backup_retention", "deletion_protection"}, "AWS", "RDS"),
    # Azure
    ({"https_only", "min_tls_version", "allow_public_access", "soft_delete_blobs"}, "Azure", "Storage"),
    ({"disk_encryption", "just_in_time_access", "auto_patching"},                  "Azure", "VirtualMachine"),
    ({"soft_delete", "purge_protection", "rbac_authorization"},                    "Azure", "KeyVault"),
    # GCP
    ({"uniform_bucket_level_access", "public_access"},     "GCP", "CloudStorage"),
    ({"os_login", "serial_port_enabled", "shielded_vm"},   "GCP", "ComputeEngine"),
]

def _detect_cloud_service(config: dict) -> tuple[str, str]:
    keys = set(config.keys())
    best_score, best_cloud, best_service = 0, "AWS", "S3"
    for hint_keys, cloud, service in _FIELD_HINTS:
        score = len(hint_keys & keys)
        if score > best_score:
            best_score, best_cloud, best_service = score, cloud, service
    return best_cloud, best_service


# ---------------------------------------------------------------------------
# Bulk scan endpoint
# ---------------------------------------------------------------------------

@app.post("/api/scan/bulk")
def scan_bulk(body: dict):
    """
    Scan multiple resources at once.

    Accepted body shapes:
      { "resources": [ { "name": ..., "config": {...}, "cloud"?: ..., "service"?: ... }, ... ] }
      [ { "name": ..., "config": {...} }, ... ]   (bare array)

    cloud + service are auto-detected from config fields if omitted.
    """
    from backend.compliance.scanner import scan_resource as _scan_resource

    raw_list = body if isinstance(body, list) else body.get("resources", [])
    if not raw_list:
        raise HTTPException(400, "No resources provided. Send { \"resources\": [...] }")

    if len(raw_list) > 200:
        raise HTTPException(400, "Maximum 200 resources per bulk scan.")

    results = []
    for i, item in enumerate(raw_list):
        if "config" not in item:
            raise HTTPException(400, f"Resource at index {i} is missing a 'config' field.")

        cfg = item["config"]
        cloud   = item.get("cloud")   or _detect_cloud_service(cfg)[0]
        service = item.get("service") or _detect_cloud_service(cfg)[1]
        # Re-run together when cloud was given but service wasn't
        if item.get("cloud") and not item.get("service"):
            _, service = _detect_cloud_service(cfg)

        resource = {
            "resource_id": item.get("resource_id") or f"bulk-{i}",
            "name":        item.get("name")        or item.get("resource_id") or f"Resource-{i+1}",
            "cloud":       cloud,
            "service":     service,
            "region":      item.get("region", "unknown"),
            "tags":        item.get("tags", {}),
            "config":      cfg,
        }

        scan = _scan_resource(resource)
        scan.risk_score = predict_risk(_ml_pipeline, cfg)
        r = _scan_to_dict(scan)
        r["config"] = cfg
        results.append(r)

    # Aggregate summary
    total       = len(results)
    non_compl   = sum(1 for r in results if not r["compliant"])
    crit        = sum(1 for r in results for v in r["violations"] if v["severity"] == "CRITICAL")
    high        = sum(1 for r in results for v in r["violations"] if v["severity"] == "HIGH")
    avg_risk    = sum(r["risk_score"] for r in results) / total if total else 0

    by_cloud: dict = {}
    for r in results:
        c = r["cloud"]
        by_cloud.setdefault(c, {"total": 0, "non_compliant": 0})
        by_cloud[c]["total"] += 1
        if not r["compliant"]:
            by_cloud[c]["non_compliant"] += 1

    fw_counts: dict = {}
    for r in results:
        for v in r["violations"]:
            fw_counts[v["framework"]] = fw_counts.get(v["framework"], 0) + 1

    return {
        "summary": {
            "total_resources": total,
            "compliant":       total - non_compl,
            "non_compliant":   non_compl,
            "compliance_rate": round((total - non_compl) / total * 100, 1) if total else 100,
            "critical_violations": crit,
            "high_violations": high,
            "avg_risk_score":  round(avg_risk, 3),
            "by_cloud":        by_cloud,
            "violations_by_framework": fw_counts,
        },
        "resources": sorted(results, key=lambda r: r["risk_score"], reverse=True),
    }


# ---------------------------------------------------------------------------
# Sample files download
# ---------------------------------------------------------------------------

@app.get("/api/samples/{filename}")
def download_sample(filename: str):
    allowed = {"compliant.json", "non_compliant.json"}
    if filename not in allowed:
        raise HTTPException(404, "Sample not found")
    sample_path = Path(__file__).parent.parent / "data" / "samples" / filename
    return FileResponse(str(sample_path), media_type="application/json",
                        headers={"Content-Disposition": f'attachment; filename="{filename}"'})


# ---------------------------------------------------------------------------
# Serve frontend
# ---------------------------------------------------------------------------

app.mount("/static", StaticFiles(directory=str(FRONTEND_PATH)), name="static")


@app.get("/")
def index():
    return FileResponse(str(FRONTEND_PATH / "index.html"))
