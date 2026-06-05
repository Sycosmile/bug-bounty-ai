"""
Passive recon skill — Wayback Machine + Certificate Transparency.

Data sources (all read-only, no active probing):
  1. crt.sh              — certificate transparency log search
  2. Wayback Machine CDX — historical URL enumeration
  3. web.archive.org     — robots.txt history

Findings emitted:
  - Subdomains found via CT logs not in active recon
  - Sensitive historical URLs (admin, backup, config, .env, .git, etc.)
  - Decommissioned endpoints that may have been re-exposed
"""
from __future__ import annotations

import logging
import re
import time
from urllib.parse import urlparse

import requests

from config import API_TIMEOUT
from core.context import Context
from core.models import Finding, Severity, FindingCategory, Proof

logger = logging.getLogger(__name__)

_SENSITIVE_PATTERNS = [
    (r"\.env$",                  "Historical .env file in Wayback Machine",          Severity.HIGH),
    (r"\.git/",                  "Historical .git directory in Wayback Machine",      Severity.HIGH),
    (r"backup",                  "Historical backup file in Wayback Machine",         Severity.MEDIUM),
    (r"\.sql$",                  "Historical SQL dump in Wayback Machine",            Severity.HIGH),
    (r"wp-admin",                "Historical WordPress admin URL in Wayback Machine", Severity.MEDIUM),
    (r"phpmyadmin",              "Historical phpMyAdmin URL in Wayback Machine",      Severity.HIGH),
    (r"admin",                   "Historical admin panel URL in Wayback Machine",     Severity.MEDIUM),
    (r"config\.(php|json|yml)$", "Historical config file in Wayback Machine",        Severity.HIGH),
    (r"\.bak$|\.old$|\.orig$",   "Historical backup file extension",                 Severity.MEDIUM),
    (r"swagger|api-docs|graphql","Historical API documentation URL",                 Severity.LOW),
]


def _bare_domain(target: str) -> str:
    target = re.sub(r"^https?://", "", target)
    return target.split("/")[0].split(":")[0]


# ── 1. Certificate Transparency (crt.sh) ─────────────────────────────────────

def _ct_subdomains(domain: str) -> list[str]:
    url = f"https://crt.sh/?q=%.{domain}&output=json"
    try:
        r = requests.get(url, timeout=15)
        if r.status_code != 200:
            return []
        entries = r.json()
        subs: set[str] = set()
        for e in entries:
            for name in e.get("name_value", "").splitlines():
                name = name.strip().lstrip("*.")
                if name.endswith(domain) and name != domain:
                    subs.add(name.lower())
        return sorted(subs)
    except Exception as e:
        logger.debug(f"crt.sh failed: {e}")
        return []


# ── 2. Wayback Machine CDX ────────────────────────────────────────────────────

def _wayback_urls(domain: str, limit: int = 500) -> list[str]:
    url = (
        f"http://web.archive.org/cdx/search/cdx"
        f"?url=*.{domain}/*&output=text&fl=original&collapse=urlkey"
        f"&limit={limit}&filter=statuscode:200"
    )
    try:
        r = requests.get(url, timeout=20)
        if r.status_code != 200:
            return []
        return [line.strip() for line in r.text.splitlines() if line.strip()]
    except Exception as e:
        logger.debug(f"Wayback CDX failed: {e}")
        return []


def _wayback_robots(domain: str) -> list[str]:
    """Pull robots.txt history — often reveals hidden paths."""
    url = f"https://web.archive.org/web/*/https://{domain}/robots.txt"
    try:
        r = requests.get(
            f"http://web.archive.org/cdx/search/cdx"
            f"?url={domain}/robots.txt&output=text&fl=original&limit=1",
            timeout=10
        )
        if r.status_code != 200 or not r.text.strip():
            return []
        robots_url = f"https://web.archive.org/web/latest/{domain}/robots.txt"
        rb = requests.get(robots_url, timeout=10)
        disallowed = re.findall(r"Disallow:\s*(\S+)", rb.text)
        return [f"https://{domain}{p}" for p in disallowed if p and p != "/"]
    except Exception as e:
        logger.debug(f"Wayback robots failed: {e}")
        return []


# ── skill entrypoint ─────────────────────────────────────────────────────────

def run(context: Context) -> Context:
    logger.info("Starting passive recon (CT logs + Wayback Machine)")
    domain = _bare_domain(context.target)

    # ── CT subdomains ─────────────────────────────────────────────────────────
    ct_subs = _ct_subdomains(domain)
    new_subs = [s for s in ct_subs if s not in context.subdomains]
    for s in new_subs:
        context.subdomains.append(s)

    logger.info(f"CT logs: {len(ct_subs)} subdomains found, {len(new_subs)} new")

    if ct_subs:
        context.add_finding(Finding(
            title=f"Certificate transparency: {len(ct_subs)} subdomains enumerated",
            severity=Severity.INFO,
            category=FindingCategory.RECON,
            source="passive_recon",
            target=domain,
            description=(
                f"crt.sh CT logs reveal {len(ct_subs)} subdomains. "
                f"New (not found by active recon): {', '.join(new_subs[:10]) or 'none'}."
            ),
            remediation="Review all discovered subdomains; ensure none are unintentionally exposed.",
            confidence=0.99,
            proof=Proof(
                verified=True,
                method="crt.sh_ct_log",
                request=f"GET https://crt.sh/?q=%.{domain}&output=json",
                response=f"{len(ct_subs)} subdomains: {', '.join(ct_subs[:20])}",
            ),
            references=["https://crt.sh", "https://certificate.transparency.dev"],
        ))

    # Flag dev/test subdomains found via CT
    dev_kw = {"dev", "test", "staging", "uat", "qa", "sandbox", "demo", "old", "legacy"}
    dev_ct = [s for s in ct_subs if any(k in s.split(".")[0] for k in dev_kw)]
    for sub in dev_ct[:5]:
        context.add_finding(Finding(
            title=f"Dev/test subdomain in CT logs: {sub}",
            severity=Severity.MEDIUM,
            category=FindingCategory.RECON,
            source="passive_recon",
            target=sub,
            description="Dev/staging subdomains in CT logs are permanent and cannot be removed.",
            remediation="Ensure this host is not publicly reachable; use private CAs for internal certs.",
            confidence=0.9,
            proof=Proof(verified=True, method="crt.sh_ct_log",
                        request=f"GET https://crt.sh/?q=%.{domain}&output=json",
                        response=f"Found: {sub}"),
        ))

    # ── Wayback Machine ───────────────────────────────────────────────────────
    time.sleep(0.5)   # be polite to archive.org
    wb_urls = _wayback_urls(domain)
    logger.info(f"Wayback Machine: {len(wb_urls)} historical URLs")

    seen_findings: set[str] = set()
    for url in wb_urls:
        url_lower = url.lower()
        for pattern, title, severity in _SENSITIVE_PATTERNS:
            if re.search(pattern, url_lower) and title not in seen_findings:
                seen_findings.add(title)
                context.add_finding(Finding(
                    title=title,
                    severity=severity,
                    category=FindingCategory.RECON,
                    source="passive_recon",
                    target=url,
                    description=(
                        f"Wayback Machine has a historical snapshot of {url}. "
                        "Even if removed, it may be cached or re-exposed."
                    ),
                    remediation="Verify the resource is no longer accessible; check if it was committed to source control.",
                    confidence=0.75,
                    proof=Proof(
                        verified=True,
                        method="wayback_cdx",
                        request=f"CDX query for *.{domain}/*",
                        response=f"Historical URL: {url}",
                    ),
                ))

    # ── robots.txt history ────────────────────────────────────────────────────
    robots_paths = _wayback_robots(domain)
    if robots_paths:
        context.add_finding(Finding(
            title=f"robots.txt history reveals {len(robots_paths)} disallowed path(s)",
            severity=Severity.LOW,
            category=FindingCategory.RECON,
            source="passive_recon",
            target=f"https://{domain}/robots.txt",
            description=(
                f"Historical robots.txt discloses: {', '.join(robots_paths[:10])}. "
                "These paths were intentionally hidden and may warrant investigation."
            ),
            remediation="Audit disallowed paths; avoid using robots.txt as a security control.",
            confidence=0.85,
            proof=Proof(verified=True, method="wayback_robots",
                        request=f"Wayback latest {domain}/robots.txt",
                        response="\n".join(robots_paths[:20])),
        ))

    context.insights.append({
        "type":          "passive_recon",
        "ct_subdomains": len(ct_subs),
        "new_subdomains": len(new_subs),
        "wayback_urls":  len(wb_urls),
        "robots_paths":  len(robots_paths),
    })

    logger.info("Passive recon complete")
    return context


skill = {"name": "passive_recon", "run": run}
