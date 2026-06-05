"""
Verify skill — runs the confirmation engine over all findings.

Runs after all discovery skills. For each finding:
  1. Routes to the appropriate verifier in verify/
  2. Attaches Proof to verified findings
  3. Runs TLS checks on all HTTPS targets
  4. Runs clickjacking verification on HTML endpoints
  5. Runs header verification on header-related findings
  
Respects ProofMode — in PROOF_ONLY mode, unverified findings are
still stored internally but filtered out of context.findings.
"""
from __future__ import annotations
import logging
import re
from core.context import Context
from core.models import Finding, Severity, FindingCategory, ProofMode
from verify import confirm, clickjacking, tls_check, headers

logger = logging.getLogger(__name__)


def _bare_host(url: str) -> str:
    url = re.sub(r"^https?://", "", url)
    return url.split("/")[0].split(":")[0]


def run(context: Context) -> Context:
    logger.info("Starting verification pass")
    findings = context.all_findings()

    # ── 1. General confirmation engine ────────────────────────────────────────
    verified, attempted = confirm.verify_all(findings, context)
    logger.info(f"Confirmation engine: {verified}/{attempted} verified")

    # ── 2. Header-specific verification ──────────────────────────────────────
    header_keywords = ["missing", "header", "hsts", "x-frame", "x-content",
                       "referrer", "permissions", "csp"]
    for f in findings:
        if not f.is_verified and any(kw in f.title.lower() for kw in header_keywords):
            result = headers.verify(f)
            if result:
                logger.info(f"✓ Header verified: {f.title}")
            else:
                # Header IS present — mark as false positive
                f.proof.method = "false_positive_header_present"

    # ── 3. Clickjacking verification on HTML targets ──────────────────────────
    seen_cj_targets: set[str] = set()
    for svc in context.services:
        url = svc.split(" ")[0]
        if not url.startswith("http"):
            continue
        if url in seen_cj_targets:
            continue
        seen_cj_targets.add(url)
        cj_finding = clickjacking.verify(url)
        if cj_finding:
            context.add_finding(cj_finding)
            logger.info(f"✓ Clickjacking confirmed: {url}")

    # Also check the original target
    target_url = context.target.rstrip("/")
    if target_url not in seen_cj_targets:
        cj_finding = clickjacking.verify(target_url)
        if cj_finding:
            context.add_finding(cj_finding)
            logger.info(f"✓ Clickjacking confirmed: {target_url}")

    # ── 4. TLS checks on all HTTPS hosts ─────────────────────────────────────
    tls_hosts: set[str] = set()
    for sub in context.subdomains:
        tls_hosts.add(_bare_host(sub))
    tls_hosts.add(_bare_host(context.target))

    for host in tls_hosts:
        tls_findings = tls_check.verify(host)
        for f in tls_findings:
            context.add_finding(f)
            logger.info(f"✓ TLS issue confirmed: {f.title} @ {host}")

    # ── 5. Summary ────────────────────────────────────────────────────────────
    all_f    = context.all_findings()
    verified_count = sum(1 for f in all_f if f.is_verified)
    total    = len(all_f)
    visible  = len(context.findings)   # respects proof_mode filter

    logger.info(
        f"Verification complete: {verified_count}/{total} verified | "
        f"visible (proof_mode={context.proof_mode.value}): {visible}"
    )

    if context.proof_mode != ProofMode.ALL:
        dropped = total - visible
        if dropped:
            logger.info(f"Proof mode '{context.proof_mode.value}': {dropped} unverified findings suppressed")

    return context


skill = {"name": "verify", "run": run}
