"""Inspector skill — cross-skill synthesis and risk correlation."""
from __future__ import annotations
import logging
from collections import Counter
from core.context import Context
from core.models import Finding, Severity, FindingCategory

logger = logging.getLogger(__name__)


def run(context: Context) -> Context:
    logger.info("Running cross-skill risk correlation")
    findings = context.all_findings()

    # ── dev/test subdomains ───────────────────────────────────────────────────
    dev_kw = {"dev", "test", "staging", "debug", "uat", "qa", "sandbox", "demo"}
    dev_subs = [s for s in context.subdomains if any(k in s.lower() for k in dev_kw)]
    if dev_subs:
        context.add_finding(Finding(
            title=f"Dev/test environment publicly reachable: {', '.join(dev_subs[:3])}",
            severity=Severity.MEDIUM,
            category=FindingCategory.MISCONFIGURED,
            source="inspector",
            target=context.target,
            description="Dev environments often have relaxed controls, debug endpoints, and weaker credentials.",
            remediation="Restrict dev/staging hosts to VPN or internal networks only.",
            confidence=0.8,
        ))

    # ── auth cluster ──────────────────────────────────────────────────────────
    auth_f = [f for f in findings if f.category == FindingCategory.AUTH]
    if len(auth_f) >= 2:
        context.add_finding(Finding(
            title=f"Systemic access control weakness ({len(auth_f)} auth findings)",
            severity=Severity.HIGH,
            category=FindingCategory.AUTH,
            source="inspector",
            target=context.target,
            description="Multiple auth/authorisation issues suggest systemic broken access control.",
            remediation="Conduct a full access control review; enforce consistent auth middleware.",
            confidence=0.85,
        ))

    # ── info-leak cluster ─────────────────────────────────────────────────────
    leak_f = [f for f in findings if f.category == FindingCategory.INFO_LEAK]
    if len(leak_f) >= 2:
        context.add_finding(Finding(
            title=f"Multiple information disclosure issues ({len(leak_f)} findings)",
            severity=Severity.MEDIUM,
            category=FindingCategory.INFO_LEAK,
            source="inspector",
            target=context.target,
            description="Multiple info-leak findings significantly reduce attacker effort.",
            remediation="Audit all response headers and error pages; apply server hardening.",
            confidence=0.8,
        ))

    # ── missing headers cluster ───────────────────────────────────────────────
    hdr_f = [f for f in findings if "missing" in f.title.lower() and "header" in f.title.lower()]
    if len(hdr_f) >= 3:
        context.add_finding(Finding(
            title=f"No systematic security header hardening ({len(hdr_f)} headers missing)",
            severity=Severity.MEDIUM,
            category=FindingCategory.WEB,
            source="inspector",
            target=context.target,
            description=f"{len(hdr_f)} recommended security headers absent — no header hardening middleware detected.",
            remediation="Add a global middleware layer to inject security headers. See https://securityheaders.com",
            confidence=0.95,
            references=["https://owasp.org/www-project-secure-headers/"],
        ))

    # ── critical + high concentration ────────────────────────────────────────
    crit_high = [f for f in findings if f.effective_severity in (Severity.CRITICAL, Severity.HIGH)]
    if len(crit_high) >= 3:
        context.add_finding(Finding(
            title=f"High concentration of critical/high findings ({len(crit_high)})",
            severity=Severity.HIGH,
            category=FindingCategory.OTHER,
            source="inspector",
            target=context.target,
            description="Unusually high density of critical/high findings — surface appears broadly exposed.",
            remediation="Prioritise immediate triage of all critical findings before lower severities.",
            confidence=0.9,
        ))

    sev_counts = Counter(f.effective_severity.value for f in findings)
    context.insights.append({
        "type":      "risk_summary",
        "by_severity": dict(sev_counts),
        "verified":  sum(1 for f in findings if f.is_verified),
        "total":     len(findings),
        "attack_surface": {
            "hosts":     len(context.subdomains),
            "services":  len(context.services),
            "endpoints": len(context.endpoints),
        },
    })

    logger.info(f"Inspector complete — {len(context.insights)} insights")
    return context


skill = {"name": "inspector", "run": run}
