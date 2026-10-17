"""
API integration tests — one test per functional requirement (FR1–FR12).

Each test exercises the REST API via FastAPI's TestClient (which wraps
httpx) and asserts on the HTTP status code and a representative payload
field. The tests collectively confirm that every functional requirement
listed in §4.2.1 of the dissertation is demonstrable at the API level.

Run with:  python -m pytest tests/test_api.py -v
"""

import pytest
from fastapi.testclient import TestClient

from backend.main import app


@pytest.fixture(scope="module")
def client():
    """Spin up a TestClient that runs the FastAPI lifespan (load resources,
    scan them, train the ML model, score every resource)."""
    with TestClient(app) as c:
        yield c


# ---------------------------------------------------------------------------
# FR1 — Scan AWS, Azure and GCP configurations
# FR2 — Evaluate against CIS, NIST and ISO controls
# ---------------------------------------------------------------------------
def test_fr1_summary_covers_all_three_clouds(client):
    """FR1: summary must list all three supported clouds."""
    r = client.get("/api/summary")
    assert r.status_code == 200
    by_cloud = r.json()["by_cloud"]
    assert {"AWS", "Azure", "GCP"} <= set(by_cloud.keys())


def test_fr2_violations_by_framework_includes_cis(client):
    """FR2: aggregated framework counts must include CIS at minimum."""
    r = client.get("/api/summary")
    assert r.status_code == 200
    frameworks = r.json()["violations_by_framework"]
    assert "CIS" in frameworks
    assert frameworks["CIS"] > 0


# ---------------------------------------------------------------------------
# FR3 — Predict a continuous risk score per resource using ML
# ---------------------------------------------------------------------------
def test_fr3_resources_have_risk_score(client):
    """FR3: every resource must have a continuous risk score in [0, 1]."""
    r = client.get("/api/resources")
    assert r.status_code == 200
    body = r.json()
    assert len(body) > 0
    for resource in body:
        assert "risk_score" in resource
        assert 0.0 <= resource["risk_score"] <= 1.0


# ---------------------------------------------------------------------------
# FR4 — Produce an explanation per violation (gated by ANTHROPIC_API_KEY)
# ---------------------------------------------------------------------------
def test_fr4_explain_endpoint_exists(client):
    """FR4: /api/resources/{id}/explain endpoint exists.

    Returns 200 when ANTHROPIC_API_KEY is configured, 503 otherwise; either
    response confirms the route is registered and validates the resource.
    """
    listing = client.get("/api/resources").json()
    assert listing, "expected at least one resource to be loaded"
    resource_id = listing[0]["resource_id"]
    r = client.post(f"/api/resources/{resource_id}/explain")
    assert r.status_code in (200, 503)


# ---------------------------------------------------------------------------
# FR5 — Dashboard presents aggregate compliance posture
# ---------------------------------------------------------------------------
def test_fr5_summary_returns_aggregate_metrics(client):
    r = client.get("/api/summary")
    assert r.status_code == 200
    body = r.json()
    for key in (
        "total_resources", "compliant", "non_compliant",
        "compliance_rate", "critical_violations",
        "high_violations", "avg_risk_score",
    ):
        assert key in body, f"summary is missing aggregate field {key}"


# ---------------------------------------------------------------------------
# FR6 — Browse, filter and inspect resources
# ---------------------------------------------------------------------------
def test_fr6_filter_resources_by_cloud(client):
    """FR6: /api/resources accepts cloud / compliant / service filters."""
    r = client.get("/api/resources", params={"cloud": "AWS"})
    assert r.status_code == 200
    body = r.json()
    assert len(body) > 0
    assert all(item["cloud"] == "AWS" for item in body)

    # Single resource detail
    rid = body[0]["resource_id"]
    detail = client.get(f"/api/resources/{rid}")
    assert detail.status_code == 200
    payload = detail.json()
    assert payload["resource_id"] == rid
    assert "config" in payload
    assert "violations" in payload


# ---------------------------------------------------------------------------
# FR7 — Accept user-supplied configurations via JSON upload (bulk)
# ---------------------------------------------------------------------------
def test_fr7_bulk_scan_accepts_user_json(client):
    """FR7: /api/scan/bulk accepts an array of user-supplied configs."""
    body = {
        "resources": [
            {
                "name": "test-bucket",
                "cloud": "AWS",
                "service": "S3",
                "config": {"public_access_block": False, "versioning": False},
            },
            {
                "name": "test-vm",
                "cloud": "Azure",
                "service": "VirtualMachine",
                "config": {"disk_encryption": True, "auto_patching": True, "public_ip": False},
            },
        ]
    }
    r = client.post("/api/scan/bulk", json=body)
    assert r.status_code == 200
    out = r.json()
    assert out["summary"]["total_resources"] == 2
    assert len(out["resources"]) == 2


# ---------------------------------------------------------------------------
# FR8 — Display ML feature importances
# ---------------------------------------------------------------------------
def test_fr8_feature_importances_endpoint(client):
    """FR8: /api/ml/importances returns the top-k features driving the score."""
    r = client.get("/api/ml/importances")
    assert r.status_code == 200
    body = r.json()
    assert isinstance(body, list)
    assert len(body) > 0
    for item in body:
        assert "feature" in item and "importance" in item
        assert isinstance(item["importance"], float)


# ---------------------------------------------------------------------------
# FR9 — Provide downloadable sample configurations
# ---------------------------------------------------------------------------
def test_fr9_samples_are_downloadable(client):
    """FR9: /api/samples/{filename} serves the bundled sample JSON files."""
    for filename in ("compliant.json", "non_compliant.json"):
        r = client.get(f"/api/samples/{filename}")
        assert r.status_code == 200
        assert "application/json" in r.headers.get("content-type", "")
        # Body must parse as JSON
        assert r.json()


# ---------------------------------------------------------------------------
# FR10 — Auto-detect cloud and service from config fields
# ---------------------------------------------------------------------------
def test_fr10_bulk_scan_auto_detects_cloud_and_service(client):
    """FR10: when cloud/service are omitted, the API infers them from
    characteristic config fields (e.g. `public_access_block` → AWS S3)."""
    body = {
        "resources": [
            {
                "name": "mystery-bucket",
                "config": {
                    "public_access_block": False,
                    "versioning": True,
                    "encryption": "aws:kms",
                },
            }
        ]
    }
    r = client.post("/api/scan/bulk", json=body)
    assert r.status_code == 200
    out = r.json()
    assert out["resources"][0]["cloud"] == "AWS"
    assert out["resources"][0]["service"] == "S3"


# ---------------------------------------------------------------------------
# FR11 — Cap bulk uploads at 200 resources
# ---------------------------------------------------------------------------
def test_fr11_bulk_scan_enforces_200_resource_cap(client):
    """FR11: requests exceeding 200 resources must return HTTP 400."""
    big_body = {
        "resources": [
            {"name": f"r{i}", "cloud": "AWS", "service": "S3", "config": {}}
            for i in range(201)
        ]
    }
    r = client.post("/api/scan/bulk", json=big_body)
    assert r.status_code == 400
    assert "200" in r.json().get("detail", "")


# ---------------------------------------------------------------------------
# FR12 — Expose all functionality through a documented REST API
# ---------------------------------------------------------------------------
def test_fr12_openapi_schema_is_published(client):
    """FR12: FastAPI's /openapi.json must list every documented endpoint."""
    r = client.get("/openapi.json")
    assert r.status_code == 200
    schema = r.json()
    paths = set(schema["paths"].keys())
    required = {
        "/api/summary",
        "/api/resources",
        "/api/resources/{resource_id}",
        "/api/resources/{resource_id}/explain",
        "/api/ml/importances",
        "/api/scan/custom",
        "/api/scan/bulk",
        "/api/samples/{filename}",
    }
    missing = required - paths
    assert not missing, f"OpenAPI schema is missing required paths: {missing}"
