"""
Unit tests for the compliance rule engine.

One compliant and one non-compliant case per rule, giving 41 × 2 = 82 tests.
Each test invokes the rule lambda directly and asserts on the return shape.

Run with:  python -m pytest tests/test_rules.py -v
"""

import pytest

from backend.compliance.scanner import RULES, ViolationResult

# ---------------------------------------------------------------------------
# Test cases: (cloud, service, rule_index, compliant_config, non_compliant_config)
# Every rule listed below has exactly one compliant config (rule returns None)
# and one non-compliant config (rule returns a ViolationResult).
# ---------------------------------------------------------------------------

RULE_CASES = [
    # ── AWS S3 (5) ─────────────────────────────────────────────────────────
    ("AWS", "S3", 0, {"public_access_block": True},  {"public_access_block": False}),
    ("AWS", "S3", 1, {"versioning": True},           {"versioning": False}),
    ("AWS", "S3", 2, {"encryption": "aws:kms"},      {"encryption": None}),
    ("AWS", "S3", 3, {"logging": True},              {"logging": False}),
    ("AWS", "S3", 4, {"bucket_acl": "private"},      {"bucket_acl": "public-read"}),

    # ── AWS EC2 (4) ────────────────────────────────────────────────────────
    ("AWS", "EC2", 0, {"ssh_unrestricted": False},   {"ssh_unrestricted": True}),
    ("AWS", "EC2", 1, {"imdsv2": "required"},        {"imdsv2": "optional"}),
    ("AWS", "EC2", 2, {"ebs_encrypted": True},       {"ebs_encrypted": False}),
    ("AWS", "EC2", 3, {"public_ip": False},          {"public_ip": True}),

    # ── AWS IAM (6) ────────────────────────────────────────────────────────
    ("AWS", "IAM", 0, {"root_mfa": True},                  {"root_mfa": False}),
    ("AWS", "IAM", 1, {"root_access_keys": False},         {"root_access_keys": True}),
    ("AWS", "IAM", 2, {"password_policy_strong": True},    {"password_policy_strong": False}),
    ("AWS", "IAM", 3, {"mfa_enforced": True},              {"mfa_enforced": False}),
    ("AWS", "IAM", 4, {"min_password_length": 16},         {"min_password_length": 8}),
    ("AWS", "IAM", 5, {"access_key_rotation_days": 30},    {"access_key_rotation_days": 180}),

    # ── AWS CloudTrail (4) ─────────────────────────────────────────────────
    ("AWS", "CloudTrail", 0, {"enabled": True},            {"enabled": False}),
    ("AWS", "CloudTrail", 1, {"multi_region": True},       {"multi_region": False}),
    ("AWS", "CloudTrail", 2, {"log_validation": True},     {"log_validation": False}),
    ("AWS", "CloudTrail", 3, {"s3_bucket_logging": True},  {"s3_bucket_logging": False}),

    # ── AWS RDS (4) ────────────────────────────────────────────────────────
    ("AWS", "RDS", 0, {"publicly_accessible": False},    {"publicly_accessible": True}),
    ("AWS", "RDS", 1, {"encryption": True},              {"encryption": False}),
    ("AWS", "RDS", 2, {"backup_retention": 14},          {"backup_retention": 1}),
    ("AWS", "RDS", 3, {"deletion_protection": True},     {"deletion_protection": False}),

    # ── Azure Storage (5) ──────────────────────────────────────────────────
    ("Azure", "Storage", 0, {"https_only": True},           {"https_only": False}),
    ("Azure", "Storage", 1, {"allow_public_access": False}, {"allow_public_access": True}),
    ("Azure", "Storage", 2, {"min_tls_version": "TLS1_2"},  {"min_tls_version": "TLS1_0"}),
    ("Azure", "Storage", 3, {"encryption_enabled": True},   {"encryption_enabled": False}),
    ("Azure", "Storage", 4, {"soft_delete_blobs": True},    {"soft_delete_blobs": False}),

    # ── Azure VirtualMachine (3) ───────────────────────────────────────────
    ("Azure", "VirtualMachine", 0, {"disk_encryption": True}, {"disk_encryption": False}),
    ("Azure", "VirtualMachine", 1, {"auto_patching": True},   {"auto_patching": False}),
    ("Azure", "VirtualMachine", 2, {"public_ip": False},      {"public_ip": True}),

    # ── Azure KeyVault (4) ─────────────────────────────────────────────────
    ("Azure", "KeyVault", 0, {"soft_delete": True},         {"soft_delete": False}),
    ("Azure", "KeyVault", 1, {"purge_protection": True},    {"purge_protection": False}),
    ("Azure", "KeyVault", 2, {"rbac_authorization": True},  {"rbac_authorization": False}),
    ("Azure", "KeyVault", 3, {"firewall_enabled": True},    {"firewall_enabled": False}),

    # ── GCP CloudStorage (4) ───────────────────────────────────────────────
    ("GCP", "CloudStorage", 0, {"public_access": False},                 {"public_access": True}),
    ("GCP", "CloudStorage", 1, {"uniform_bucket_level_access": True},    {"uniform_bucket_level_access": False}),
    ("GCP", "CloudStorage", 2, {"versioning": True},                     {"versioning": False}),
    ("GCP", "CloudStorage", 3, {"logging": True},                        {"logging": False}),

    # ── GCP ComputeEngine (2) ──────────────────────────────────────────────
    ("GCP", "ComputeEngine", 0, {"os_login": True},              {"os_login": False}),
    ("GCP", "ComputeEngine", 1, {"serial_port_enabled": False},  {"serial_port_enabled": True}),
]


def _rule(cloud: str, service: str, idx: int):
    return RULES[cloud][service][idx]


def _case_id(case):
    cloud, service, idx, *_ = case
    return f"{cloud}-{service}-{idx}"


# ---------------------------------------------------------------------------
# 41 compliant tests — each rule should return None for the compliant config
# ---------------------------------------------------------------------------
@pytest.mark.parametrize("case", RULE_CASES, ids=[_case_id(c) for c in RULE_CASES])
def test_rule_passes_for_compliant_config(case):
    cloud, service, idx, compliant_cfg, _ = case
    rule = _rule(cloud, service, idx)
    result = rule(compliant_cfg)
    assert result is None, (
        f"Rule {cloud}/{service}/{idx} should pass for compliant config {compliant_cfg!r}, "
        f"got violation: {result}"
    )


# ---------------------------------------------------------------------------
# 41 non-compliant tests — each rule should return a ViolationResult
# ---------------------------------------------------------------------------
@pytest.mark.parametrize("case", RULE_CASES, ids=[_case_id(c) for c in RULE_CASES])
def test_rule_fires_for_noncompliant_config(case):
    cloud, service, idx, _, noncompliant_cfg = case
    rule = _rule(cloud, service, idx)
    result = rule(noncompliant_cfg)
    assert result is not None, (
        f"Rule {cloud}/{service}/{idx} should fire for non-compliant config {noncompliant_cfg!r}"
    )
    assert isinstance(result, ViolationResult)
    assert result.framework in {"CIS", "NIST", "ISO"}
    assert result.severity in {"LOW", "MEDIUM", "HIGH", "CRITICAL"}
    assert result.rule_id, "rule_id must be populated"
    assert result.doc_id, "doc_id must be populated"


# ---------------------------------------------------------------------------
# Coverage assertion — the test list must remain in sync with the engine
# ---------------------------------------------------------------------------
def test_all_rules_have_test_cases():
    engine_count = sum(len(rules) for s in RULES.values() for rules in s.values())
    case_count = len(RULE_CASES)
    assert case_count == engine_count, (
        f"Mismatch: engine has {engine_count} rules but RULE_CASES has {case_count}. "
        "Every rule needs both a compliant and a non-compliant test."
    )
