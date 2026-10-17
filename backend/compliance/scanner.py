"""
Compliance scanner: evaluates cloud resource configs against CIS/NIST/ISO rules.
Each rule is a pure function that returns a ViolationResult or None.
"""

from dataclasses import dataclass, field
from typing import Optional


@dataclass
class ViolationResult:
    rule_id: str
    framework: str
    control: str
    severity: str
    title: str
    detail: str
    field: str
    actual_value: object
    expected_value: object
    doc_id: str  # links to knowledge base document for RAG retrieval


@dataclass
class ScanResult:
    resource_id: str
    resource_name: str
    cloud: str
    service: str
    region: str
    compliant: bool
    violations: list[ViolationResult] = field(default_factory=list)
    risk_score: float = 0.0  # filled by ML model


# ---------------------------------------------------------------------------
# Rule definitions — one function per check, returns ViolationResult or None
# ---------------------------------------------------------------------------

def _check(config, key, expected, rule_id, framework, control, severity, title, detail, doc_id):
    actual = config.get(key)
    if actual != expected:
        return ViolationResult(
            rule_id=rule_id, framework=framework, control=control,
            severity=severity, title=title,
            detail=detail.format(actual=actual, expected=expected),
            field=key, actual_value=actual, expected_value=expected,
            doc_id=doc_id,
        )
    return None


def _check_not(config, key, bad_value, rule_id, framework, control, severity, title, detail, doc_id):
    actual = config.get(key)
    if actual == bad_value:
        return ViolationResult(
            rule_id=rule_id, framework=framework, control=control,
            severity=severity, title=title,
            detail=detail.format(actual=actual),
            field=key, actual_value=actual, expected_value=f"not {bad_value}",
            doc_id=doc_id,
        )
    return None


def _check_truthy(config, key, rule_id, framework, control, severity, title, detail, doc_id):
    actual = config.get(key)
    if not actual:
        return ViolationResult(
            rule_id=rule_id, framework=framework, control=control,
            severity=severity, title=title,
            detail=detail.format(actual=actual),
            field=key, actual_value=actual, expected_value=True,
            doc_id=doc_id,
        )
    return None


def _check_falsy(config, key, rule_id, framework, control, severity, title, detail, doc_id):
    actual = config.get(key)
    if actual:
        return ViolationResult(
            rule_id=rule_id, framework=framework, control=control,
            severity=severity, title=title,
            detail=detail.format(actual=actual),
            field=key, actual_value=actual, expected_value=False,
            doc_id=doc_id,
        )
    return None


def _check_predicate(config, key, predicate, expected_desc, rule_id, framework, control,
                     severity, title, detail, doc_id):
    """Pass if predicate(config[key]) is truthy. Used for inequalities (e.g. >= 14)."""
    actual = config.get(key)
    if not predicate(actual):
        return ViolationResult(
            rule_id=rule_id, framework=framework, control=control,
            severity=severity, title=title,
            detail=detail.format(actual=actual),
            field=key, actual_value=actual, expected_value=expected_desc,
            doc_id=doc_id,
        )
    return None


RULES = {
    "AWS": {
        # ----- S3 (5 rules) -----
        "S3": [
            lambda c: _check_truthy(c, "public_access_block", "CIS-AWS-2.1.1", "CIS", "2.1.1", "HIGH",
                "S3 bucket public access block not enabled",
                "public_access_block is '{actual}' — bucket may be publicly accessible.",
                "cis-aws-s3-1"),
            lambda c: _check_truthy(c, "versioning", "CIS-AWS-2.1.2", "CIS", "2.1.2", "MEDIUM",
                "S3 bucket versioning not enabled",
                "versioning is '{actual}' — data loss from deletion cannot be recovered.",
                "cis-aws-s3-2"),
            lambda c: _check_truthy(c, "encryption", "CIS-AWS-2.1.3", "CIS", "2.1.3", "HIGH",
                "S3 bucket server-side encryption not enabled",
                "encryption is '{actual}' — data at rest is unprotected.",
                "cis-aws-s3-3"),
            lambda c: _check_truthy(c, "logging", "CIS-AWS-2.1.4", "CIS", "2.1.4", "LOW",
                "S3 bucket access logging not enabled",
                "logging is '{actual}' — access events are not being recorded.",
                "cis-aws-s3-4"),
            lambda c: _check(c, "bucket_acl", "private", "CIS-AWS-2.1.5", "CIS", "2.1.5", "HIGH",
                "S3 bucket ACL is not restricted to private",
                "bucket_acl is '{actual}' (expected '{expected}') — non-private ACL exposes objects to other AWS accounts.",
                "cis-aws-s3-1"),
        ],
        # ----- EC2 (4 rules) -----
        "EC2": [
            lambda c: _check_falsy(c, "ssh_unrestricted", "CIS-AWS-5.1", "CIS", "5.1", "CRITICAL",
                "EC2 security group allows unrestricted SSH (port 22)",
                "ssh_unrestricted is '{actual}' — instance is exposed to brute-force attacks.",
                "cis-aws-ec2-1"),
            lambda c: _check_not(c, "imdsv2", "optional", "CIS-AWS-5.4", "CIS", "5.4", "HIGH",
                "EC2 IMDSv2 not enforced",
                "imdsv2 is '{actual}' — SSRF attacks can steal IAM credentials via metadata endpoint.",
                "cis-aws-ec2-2"),
            lambda c: _check_truthy(c, "ebs_encrypted", "CIS-AWS-5.6", "CIS", "5.6", "HIGH",
                "EC2 EBS volumes not encrypted",
                "ebs_encrypted is '{actual}' — data at rest on disk is unprotected.",
                "cis-aws-ec2-3"),
            lambda c: _check_falsy(c, "public_ip", "CIS-AWS-5.2", "CIS", "5.2", "MEDIUM",
                "EC2 instance has a public IP address",
                "public_ip is '{actual}' — workload is directly addressable from the internet.",
                "cis-aws-ec2-1"),
        ],
        # ----- IAM (6 rules) -----
        "IAM": [
            lambda c: _check_truthy(c, "root_mfa", "CIS-AWS-1.1", "CIS", "1.1", "CRITICAL",
                "Root account MFA not enabled",
                "root_mfa is '{actual}' — root account has no second factor protection.",
                "cis-aws-iam-1"),
            lambda c: _check_falsy(c, "root_access_keys", "CIS-AWS-1.4", "CIS", "1.4", "CRITICAL",
                "Root account has active access keys",
                "root_access_keys is '{actual}' — root credentials can be used programmatically.",
                "cis-aws-iam-1"),
            lambda c: _check_truthy(c, "password_policy_strong", "CIS-AWS-1.5", "CIS", "1.5", "MEDIUM",
                "IAM password policy does not meet minimum strength requirements",
                "password_policy_strong is '{actual}' — weak passwords increase credential compromise risk.",
                "cis-aws-iam-2"),
            lambda c: _check_truthy(c, "mfa_enforced", "NIST-AC-2", "NIST", "AC-2", "HIGH",
                "MFA not enforced for IAM users",
                "mfa_enforced is '{actual}' — accounts lack multi-factor authentication.",
                "nist-ac-2"),
            lambda c: _check_predicate(c, "min_password_length",
                lambda v: isinstance(v, (int, float)) and v >= 14, ">= 14",
                "CIS-AWS-1.8", "CIS", "1.8", "MEDIUM",
                "IAM minimum password length below 14 characters",
                "min_password_length is '{actual}' — passwords shorter than 14 characters are easier to brute-force.",
                "cis-aws-iam-2"),
            lambda c: _check_predicate(c, "access_key_rotation_days",
                lambda v: v is None or (isinstance(v, (int, float)) and v <= 90), "<= 90",
                "CIS-AWS-1.14", "CIS", "1.14", "MEDIUM",
                "IAM access keys not rotated within 90 days",
                "access_key_rotation_days is '{actual}' — stale access keys increase the impact of credential leaks.",
                "cis-aws-iam-2"),
        ],
        # ----- CloudTrail (4 rules) -----
        "CloudTrail": [
            lambda c: _check_truthy(c, "enabled", "CIS-AWS-3.1", "CIS", "3.1", "CRITICAL",
                "CloudTrail is not enabled",
                "enabled is '{actual}' — API activity is not being audited.",
                "cis-aws-cloudtrail-1"),
            lambda c: _check_truthy(c, "multi_region", "CIS-AWS-3.1b", "CIS", "3.1", "HIGH",
                "CloudTrail is not configured for all regions",
                "multi_region is '{actual}' — activity in other regions is not captured.",
                "cis-aws-cloudtrail-1"),
            lambda c: _check_truthy(c, "log_validation", "CIS-AWS-3.2", "CIS", "3.2", "MEDIUM",
                "CloudTrail log file validation not enabled",
                "log_validation is '{actual}' — log tampering cannot be detected.",
                "cis-aws-cloudtrail-2"),
            lambda c: _check_truthy(c, "s3_bucket_logging", "CIS-AWS-3.3", "CIS", "3.3", "MEDIUM",
                "CloudTrail S3 bucket access logging not enabled",
                "s3_bucket_logging is '{actual}' — access to the trail's S3 bucket itself is not audited.",
                "cis-aws-cloudtrail-1"),
        ],
        # ----- RDS (4 rules) -----
        "RDS": [
            lambda c: _check_falsy(c, "publicly_accessible", "CIS-AWS-2.3.1", "CIS", "2.3.1", "CRITICAL",
                "RDS instance is publicly accessible",
                "publicly_accessible is '{actual}' — database is directly reachable from the internet.",
                "cis-aws-rds-1"),
            lambda c: _check_truthy(c, "encryption", "CIS-AWS-2.3.2", "CIS", "2.3.2", "HIGH",
                "RDS instance encryption not enabled",
                "encryption is '{actual}' — database data at rest is unprotected.",
                "cis-aws-rds-2"),
            lambda c: _check_predicate(c, "backup_retention",
                lambda v: isinstance(v, (int, float)) and v >= 7, ">= 7 days",
                "CIS-AWS-2.3.3", "CIS", "2.3.3", "MEDIUM",
                "RDS backup retention below 7 days",
                "backup_retention is '{actual}' — insufficient retention reduces recovery options after an incident.",
                "cis-aws-rds-2"),
            lambda c: _check_truthy(c, "deletion_protection", "NIST-CP-9", "NIST", "CP-9", "HIGH",
                "RDS deletion protection not enabled",
                "deletion_protection is '{actual}' — database can be deleted by a single API call.",
                "cis-aws-rds-2"),
        ],
    },
    "Azure": {
        # ----- Storage (5 rules) -----
        "Storage": [
            lambda c: _check_truthy(c, "https_only", "CIS-AZ-3.1", "CIS", "3.1", "HIGH",
                "Azure Storage account does not enforce HTTPS",
                "https_only is '{actual}' — data in transit may be transmitted unencrypted.",
                "cis-azure-storage-1"),
            lambda c: _check_falsy(c, "allow_public_access", "CIS-AZ-3.7", "CIS", "3.7", "HIGH",
                "Azure Storage account allows public blob access",
                "allow_public_access is '{actual}' — blobs may be readable without authentication.",
                "cis-azure-storage-2"),
            lambda c: _check_not(c, "min_tls_version", "TLS1_0", "NIST-SC-8", "NIST", "SC-8", "HIGH",
                "Azure Storage account allows TLS 1.0",
                "min_tls_version is '{actual}' — weak TLS version accepted, violating SC-8 transmission protection.",
                "nist-sc-8"),
            lambda c: _check_truthy(c, "encryption_enabled", "CIS-AZ-3.2", "CIS", "3.2", "HIGH",
                "Azure Storage account encryption not enabled",
                "encryption_enabled is '{actual}' — data at rest in the storage account is unprotected.",
                "cis-azure-storage-1"),
            lambda c: _check_truthy(c, "soft_delete_blobs", "CIS-AZ-3.11", "CIS", "3.11", "LOW",
                "Azure Storage blob soft delete not enabled",
                "soft_delete_blobs is '{actual}' — deleted blobs cannot be recovered.",
                "cis-azure-storage-1"),
        ],
        # ----- VirtualMachine (3 rules) -----
        "VirtualMachine": [
            lambda c: _check_truthy(c, "disk_encryption", "CIS-AZ-7.2", "CIS", "7.2", "HIGH",
                "Azure VM OS disk not encrypted",
                "disk_encryption is '{actual}' — VM disk data at rest is unprotected.",
                "cis-azure-vm-1"),
            lambda c: _check_truthy(c, "auto_patching", "NIST-SI-2", "NIST", "SI-2", "MEDIUM",
                "Azure VM auto-patching not enabled",
                "auto_patching is '{actual}' — security patches are not automatically applied.",
                "nist-si-2"),
            lambda c: _check_falsy(c, "public_ip", "CIS-AZ-7.5", "CIS", "7.5", "MEDIUM",
                "Azure VM has a public IP address",
                "public_ip is '{actual}' — workload is directly addressable from the internet.",
                "cis-azure-vm-1"),
        ],
        # ----- KeyVault (4 rules) -----
        "KeyVault": [
            lambda c: _check_truthy(c, "soft_delete", "CIS-AZ-8.1", "CIS", "8.1", "HIGH",
                "Azure Key Vault soft delete not enabled",
                "soft_delete is '{actual}' — deleted vault keys cannot be recovered.",
                "cis-azure-keyvault-1"),
            lambda c: _check_truthy(c, "purge_protection", "CIS-AZ-8.2", "CIS", "8.1", "HIGH",
                "Azure Key Vault purge protection not enabled",
                "purge_protection is '{actual}' — keys can be permanently deleted immediately.",
                "cis-azure-keyvault-1"),
            lambda c: _check_truthy(c, "rbac_authorization", "CIS-AZ-8.5", "CIS", "8.5", "MEDIUM",
                "Azure Key Vault not using RBAC authorization",
                "rbac_authorization is '{actual}' — legacy access policies are coarser-grained than Azure RBAC.",
                "cis-azure-keyvault-1"),
            lambda c: _check_truthy(c, "firewall_enabled", "CIS-AZ-8.4", "CIS", "8.4", "HIGH",
                "Azure Key Vault firewall not enabled",
                "firewall_enabled is '{actual}' — vault is reachable from any network.",
                "cis-azure-keyvault-1"),
        ],
    },
    "GCP": {
        # ----- CloudStorage (4 rules) -----
        "CloudStorage": [
            lambda c: _check_falsy(c, "public_access", "CIS-GCP-5.1", "CIS", "5.1", "CRITICAL",
                "GCP Cloud Storage bucket is publicly accessible",
                "public_access is '{actual}' — bucket data is readable without authentication.",
                "cis-gcp-storage-1"),
            lambda c: _check_truthy(c, "uniform_bucket_level_access", "CIS-GCP-5.2", "CIS", "5.1", "MEDIUM",
                "GCP Cloud Storage bucket uniform access not enabled",
                "uniform_bucket_level_access is '{actual}' — ACL-based access bypasses bucket IAM.",
                "cis-gcp-storage-1"),
            lambda c: _check_truthy(c, "versioning", "CIS-GCP-5.3", "CIS", "5.3", "MEDIUM",
                "GCP Cloud Storage bucket versioning not enabled",
                "versioning is '{actual}' — accidental or malicious deletions cannot be recovered.",
                "cis-gcp-storage-1"),
            lambda c: _check_truthy(c, "logging", "CIS-GCP-5.4", "CIS", "5.4", "LOW",
                "GCP Cloud Storage bucket access logging not enabled",
                "logging is '{actual}' — access events are not being recorded.",
                "cis-gcp-storage-1"),
        ],
        # ----- ComputeEngine (2 rules) -----
        "ComputeEngine": [
            lambda c: _check_truthy(c, "os_login", "CIS-GCP-4.1", "CIS", "4.1", "HIGH",
                "GCP Compute Engine OS Login not enabled",
                "os_login is '{actual}' — SSH keys are managed manually, increasing misconfiguration risk.",
                "cis-gcp-compute-1"),
            lambda c: _check_falsy(c, "serial_port_enabled", "CIS-GCP-4.5", "CIS", "4.5", "HIGH",
                "GCP Compute Engine serial port access enabled",
                "serial_port_enabled is '{actual}' — serial port bypasses firewall and VPC controls.",
                "cis-gcp-compute-2"),
        ],
    },
}


def scan_resource(resource: dict) -> ScanResult:
    cloud = resource["cloud"]
    service = resource["service"]
    config = resource.get("config", {})

    rules = RULES.get(cloud, {}).get(service, [])
    violations = [v for r in rules if (v := r(config)) is not None]

    return ScanResult(
        resource_id=resource["resource_id"],
        resource_name=resource["name"],
        cloud=cloud,
        service=service,
        region=resource.get("region", "unknown"),
        compliant=len(violations) == 0,
        violations=violations,
    )


def scan_all(resources: list[dict]) -> list[ScanResult]:
    return [scan_resource(r) for r in resources]
