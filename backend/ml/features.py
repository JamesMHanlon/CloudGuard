"""
Feature extraction for compliance ML model.
Converts heterogeneous cloud resource configs into a fixed-length numeric vector.
"""

import numpy as np

# All possible feature keys with their default (safe/compliant) value
FEATURE_SCHEMA = [
    # S3
    ("public_access_block",         1),
    ("versioning",                  1),
    ("encryption_present",          1),  # derived: encryption is not None/null
    ("logging",                     1),
    ("bucket_acl_private",          1),  # derived: bucket_acl == "private"
    # EC2
    ("ssh_unrestricted",            0),
    ("imdsv2_required",             1),  # derived: imdsv2 == "required"
    ("ebs_encrypted",               1),
    ("public_ip",                   0),
    # IAM
    ("root_mfa",                    1),
    ("root_access_keys",            0),
    ("password_policy_strong",      1),
    ("min_password_length_ok",      1),  # derived: >= 14
    ("mfa_enforced",                1),
    # CloudTrail
    ("trail_enabled",               1),
    ("multi_region",                1),
    ("log_validation",              1),
    # RDS
    ("publicly_accessible",         0),
    ("db_encryption",               1),  # conflicts with S3 "encryption" — separate key
    ("backup_retention_ok",         1),  # derived: backup_retention > 0
    ("deletion_protection",         1),
    # Azure Storage
    ("https_only",                  1),
    ("allow_public_access",         0),
    ("tls_version_ok",              1),  # derived: not TLS1_0
    # Azure VM
    ("disk_encryption",             1),
    ("auto_patching",               1),
    ("just_in_time_access",         1),
    # Azure KeyVault
    ("soft_delete",                 1),
    ("purge_protection",            1),
    # GCP Storage
    ("gcp_public_access",           0),
    ("uniform_bucket_level_access", 1),
    # GCP Compute
    ("os_login",                    1),
    ("serial_port_enabled",         0),
    ("shielded_vm",                 1),
    # Generic / multi-cloud
    ("firewall_enabled",            1),
    ("private_endpoint",            1),
]

FEATURE_NAMES = [f[0] for f in FEATURE_SCHEMA]
SAFE_DEFAULTS = np.array([f[1] for f in FEATURE_SCHEMA], dtype=float)


def _bool(val) -> float:
    if val is None:
        return 0.0
    if isinstance(val, bool):
        return float(val)
    if isinstance(val, str):
        return float(val.lower() in ("true", "yes", "1", "enabled", "required", "aes256", "aws:kms", "cmek", "google-managed"))
    return float(bool(val))


def extract(config: dict) -> np.ndarray:
    c = config
    vec = SAFE_DEFAULTS.copy()

    idx = {name: i for i, name in enumerate(FEATURE_NAMES)}

    def set_f(name, val):
        vec[idx[name]] = float(val)

    set_f("public_access_block",         _bool(c.get("public_access_block")))
    set_f("versioning",                  _bool(c.get("versioning")))
    set_f("encryption_present",          float(bool(c.get("encryption"))))
    set_f("logging",                     _bool(c.get("logging")))
    set_f("bucket_acl_private",          float(c.get("bucket_acl") == "private"))

    set_f("ssh_unrestricted",            _bool(c.get("ssh_unrestricted")))
    set_f("imdsv2_required",             float(c.get("imdsv2") == "required"))
    set_f("ebs_encrypted",               _bool(c.get("ebs_encrypted")))
    set_f("public_ip",                   _bool(c.get("public_ip")))

    set_f("root_mfa",                    _bool(c.get("root_mfa")))
    set_f("root_access_keys",            _bool(c.get("root_access_keys")))
    set_f("password_policy_strong",      _bool(c.get("password_policy_strong")))
    set_f("min_password_length_ok",      float((c.get("min_password_length") or 0) >= 14))
    set_f("mfa_enforced",                _bool(c.get("mfa_enforced")))

    set_f("trail_enabled",               _bool(c.get("enabled")))
    set_f("multi_region",                _bool(c.get("multi_region")))
    set_f("log_validation",              _bool(c.get("log_validation")))

    set_f("publicly_accessible",         _bool(c.get("publicly_accessible")))
    # RDS encryption stored separately to avoid collision with S3 encryption field
    if "backup_retention" in c or "deletion_protection" in c:
        set_f("db_encryption",           _bool(c.get("encryption")))
        set_f("backup_retention_ok",     float((c.get("backup_retention") or 0) > 0))
        set_f("deletion_protection",     _bool(c.get("deletion_protection")))

    set_f("https_only",                  _bool(c.get("https_only")))
    set_f("allow_public_access",         _bool(c.get("allow_public_access")))
    set_f("tls_version_ok",              float(c.get("min_tls_version") not in (None, "TLS1_0", "TLS1_1")))

    set_f("disk_encryption",             _bool(c.get("disk_encryption")))
    set_f("auto_patching",               _bool(c.get("auto_patching")))
    set_f("just_in_time_access",         _bool(c.get("just_in_time_access")))

    set_f("soft_delete",                 _bool(c.get("soft_delete")))
    set_f("purge_protection",            _bool(c.get("purge_protection")))

    set_f("gcp_public_access",           _bool(c.get("public_access")))
    set_f("uniform_bucket_level_access", _bool(c.get("uniform_bucket_level_access")))

    set_f("os_login",                    _bool(c.get("os_login")))
    set_f("serial_port_enabled",         _bool(c.get("serial_port_enabled")))
    set_f("shielded_vm",                 _bool(c.get("shielded_vm")))

    set_f("firewall_enabled",            _bool(c.get("firewall_enabled")))
    set_f("private_endpoint",            _bool(c.get("private_endpoint")))

    return vec
