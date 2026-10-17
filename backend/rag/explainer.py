"""
RAG explainer: retrieves relevant compliance docs then calls Claude to generate
a concise, human-readable explanation of each violation and recommended fix.
"""

import os
import anthropic
from backend.compliance.scanner import ViolationResult, ScanResult
from backend.rag.knowledge_base import get_knowledge_base

_client: anthropic.Anthropic | None = None


def _get_client() -> anthropic.Anthropic:
    global _client
    if _client is None:
        api_key = os.environ.get("ANTHROPIC_API_KEY")
        if not api_key:
            raise RuntimeError("ANTHROPIC_API_KEY environment variable not set")
        _client = anthropic.Anthropic(api_key=api_key)
    return _client


def explain_violation(violation: ViolationResult, resource: dict) -> str:
    """Return a plain-English explanation + remediation for a single violation."""
    kb = get_knowledge_base()

    query = f"{violation.title} {violation.framework} {violation.control} {resource['service']} {resource['cloud']}"
    relevant_docs = kb.retrieve(query, k=2, filter_doc_ids=[violation.doc_id])

    context_blocks = "\n\n".join(
        f"[{doc['framework']} {doc['control']}] {doc['title']}\n{doc['text']}"
        for doc in relevant_docs
    )

    prompt = f"""You are a cloud security compliance expert. A cloud resource has a compliance violation.
Use the compliance framework documentation below to explain WHY this is a problem and HOW to fix it.
Be concise — 3 to 5 sentences maximum. End with one specific remediation command or configuration change.

## Compliance Framework Context
{context_blocks}

## Violation Details
- Resource: {resource['name']} ({resource['cloud']} / {resource['service']})
- Rule: [{violation.framework} {violation.control}] {violation.title}
- Issue: {violation.detail}
- Misconfigured field: `{violation.field}` = `{violation.actual_value}` (expected: `{violation.expected_value}`)

Explain the security risk and provide a clear remediation step."""

    client = _get_client()
    message = client.messages.create(
        model="claude-sonnet-4-6",
        max_tokens=300,
        messages=[{"role": "user", "content": prompt}],
    )
    return message.content[0].text.strip()


def explain_resource_summary(scan: ScanResult, resource: dict) -> str:
    """Return an executive summary for a resource with multiple violations."""
    if not scan.violations:
        return "This resource is fully compliant with all evaluated controls."

    kb = get_knowledge_base()

    violation_list = "\n".join(
        f"- [{v.framework} {v.control}] {v.title} (severity: {v.severity})"
        for v in scan.violations
    )

    doc_ids = list({v.doc_id for v in scan.violations})
    relevant_docs = kb.retrieve(
        " ".join(v.title for v in scan.violations), k=3, filter_doc_ids=doc_ids
    )
    context_blocks = "\n\n".join(
        f"[{doc['framework']} {doc['control']}] {doc['title']}\n{doc['text']}"
        for doc in relevant_docs
    )

    prompt = f"""You are a cloud security compliance expert. Provide a brief executive summary (4–6 sentences)
of the compliance posture for the cloud resource below. Highlight the most critical risks and
the top 2 remediation priorities. Do not repeat the full violation list — synthesise the key risks.

## Compliance Framework Context
{context_blocks}

## Resource
- Name: {resource['name']}
- Cloud: {resource['cloud']} / {resource['service']} / {resource.get('region', 'unknown')}
- Risk Score: {scan.risk_score:.0%}

## Violations Found ({len(scan.violations)} total)
{violation_list}

Provide a concise executive summary with prioritised remediation advice."""

    client = _get_client()
    message = client.messages.create(
        model="claude-sonnet-4-6",
        max_tokens=400,
        messages=[{"role": "user", "content": prompt}],
    )
    return message.content[0].text.strip()
