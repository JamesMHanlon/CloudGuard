"""
Unit tests for the ML feature extractor.

Confirms that the 36-element feature vector is extracted correctly for
canonical compliant and non-compliant inputs across the in-scope cloud
services.

Run with:  python -m pytest tests/test_features.py -v
"""

import numpy as np
import pytest

from backend.ml.features import extract, FEATURE_NAMES, FEATURE_SCHEMA, SAFE_DEFAULTS


# Index lookup so individual tests don't depend on schema ordering
IDX = {name: i for i, name in enumerate(FEATURE_NAMES)}


# ---------------------------------------------------------------------------
# Schema-level tests
# ---------------------------------------------------------------------------
def test_schema_length_is_36():
    """The feature vector must be exactly 36-dimensional (see dissertation §4.5)."""
    assert len(FEATURE_SCHEMA) == 36
    assert len(FEATURE_NAMES) == 36
    assert SAFE_DEFAULTS.shape == (36,)


def test_extract_returns_36d_vector():
    vec = extract({})
    assert isinstance(vec, np.ndarray)
    assert vec.shape == (36,)


def test_feature_names_are_unique():
    assert len(set(FEATURE_NAMES)) == len(FEATURE_NAMES)


# ---------------------------------------------------------------------------
# Per-service correctness tests
# ---------------------------------------------------------------------------
def test_s3_compliant_config_extracts_safe_values():
    cfg = {
        "public_access_block": True,
        "versioning": True,
        "encryption": "aws:kms",
        "logging": True,
        "bucket_acl": "private",
    }
    v = extract(cfg)
    assert v[IDX["public_access_block"]] == 1.0
    assert v[IDX["versioning"]] == 1.0
    assert v[IDX["encryption_present"]] == 1.0
    assert v[IDX["logging"]] == 1.0
    assert v[IDX["bucket_acl_private"]] == 1.0


def test_s3_noncompliant_public_bucket():
    cfg = {"public_access_block": False, "bucket_acl": "public-read"}
    v = extract(cfg)
    assert v[IDX["public_access_block"]] == 0.0
    assert v[IDX["bucket_acl_private"]] == 0.0


def test_ec2_imdsv2_required_is_true():
    """imdsv2_required is a derived feature: 1 iff imdsv2 == 'required'."""
    v_ok = extract({"imdsv2": "required"})
    v_bad = extract({"imdsv2": "optional"})
    assert v_ok[IDX["imdsv2_required"]] == 1.0
    assert v_bad[IDX["imdsv2_required"]] == 0.0


def test_iam_min_password_length_threshold():
    """min_password_length_ok is a derived feature: 1 iff length >= 14."""
    v_ok = extract({"min_password_length": 16})
    v_short = extract({"min_password_length": 8})
    assert v_ok[IDX["min_password_length_ok"]] == 1.0
    assert v_short[IDX["min_password_length_ok"]] == 0.0


def test_rds_backup_retention_derived():
    """backup_retention_ok is a derived feature: 1 iff retention > 0."""
    v_ok = extract({"backup_retention": 14, "deletion_protection": True})
    v_bad = extract({"backup_retention": 0, "deletion_protection": False})
    assert v_ok[IDX["backup_retention_ok"]] == 1.0
    assert v_bad[IDX["backup_retention_ok"]] == 0.0


def test_azure_storage_tls_derived_feature():
    """tls_version_ok is derived: 1 iff not TLS1_0 / TLS1_1."""
    v_ok = extract({"min_tls_version": "TLS1_2"})
    v_bad = extract({"min_tls_version": "TLS1_0"})
    assert v_ok[IDX["tls_version_ok"]] == 1.0
    assert v_bad[IDX["tls_version_ok"]] == 0.0


def test_azure_vm_disk_encryption_extracted():
    v = extract({"disk_encryption": True, "auto_patching": True, "just_in_time_access": True})
    assert v[IDX["disk_encryption"]] == 1.0
    assert v[IDX["auto_patching"]] == 1.0
    assert v[IDX["just_in_time_access"]] == 1.0


def test_gcp_storage_public_access_inverted():
    """The GCP public_access field maps to gcp_public_access (safe default = 0)."""
    v_safe = extract({"public_access": False, "uniform_bucket_level_access": True})
    v_bad = extract({"public_access": True})
    assert v_safe[IDX["gcp_public_access"]] == 0.0
    assert v_safe[IDX["uniform_bucket_level_access"]] == 1.0
    assert v_bad[IDX["gcp_public_access"]] == 1.0


def test_empty_config_does_not_crash():
    """An empty configuration must extract cleanly to a 36-dimensional vector."""
    v = extract({})
    assert v.shape == (36,)
    # Every value must be a finite real number
    assert np.all(np.isfinite(v))


def test_string_booleans_parsed_correctly():
    """String values like 'true', 'enabled', 'required' should parse as truthy."""
    v = extract({"public_access_block": "true", "imdsv2": "required"})
    assert v[IDX["public_access_block"]] == 1.0
    assert v[IDX["imdsv2_required"]] == 1.0
