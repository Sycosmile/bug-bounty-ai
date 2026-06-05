"""
Clickjacking verification module.

Verification steps (safe, non-destructive):
  1. Check X-Frame-Options header
  2. Check Content-Security-Policy frame-ancestors directive
  3. Confirm the response is HTML (non-HTML can't be framed meaningfully)
  4. Confirm there is a non-trivial body (blank pages are low-value)
  5. Optionally detect JS frame-busting code (reduces confidence)

Returns a Proof object with all evidence attached.
"""

from __future__ import annotations

import logging
import re

import requests

from config import API_TIMEOUT
from core.models import (
    Finding, Severity, FindingCategory,
    CvssVector, CvssAV, CvssAC, CvssPR, CvssUI, CvssScope, CvssImpact,
    Proof,
)

logger = logging.getLogger(__name__)

_FRAMEBUSTING_PATTERNS = [
    r"top\.location\s*=\s*self\.location",
    r"top\.location\s*!=\s*self\.location",
    r"window\.top\s*!==\s*window\.self",
    r"if\s*\(\s*window\s*!==\s*window\.top\s*\)",
    r"frameElement",
    r"X-Frame-Options",           # sometimes echoed in meta tags
]

_CVSS = CvssVector(
    AV=CvssAV.NETWORK,
    AC=CvssAC.LOW,
    PR=CvssPR.NONE,
    UI=CvssUI.REQUIRED,
    S=CvssScope.UNCHANGED,
    C=CvssImpact.LOW,
    I=CvssImpact.LOW,
    A=CvssImpact.NONE,
)  # CVSS 3.1 → 5.4 (MEDIUM) — standard clickjacking score


def verify(url: str) -> Finding | None:
    """
    Confirm clickjacking vulnerability at *url*.
    Returns a verified Finding or None if the target is protected.
    """
    try:
        r = requests.get(url, timeout=API_TIMEOUT, allow_redirects=True)
    except Exception as e:
        logger.warning(f"clickjacking verify: request failed for {url}: {e}")
        return None

    headers = {k.lower(): v for k, v in r.headers.items()}
    content_type = headers.get("content-type", "")
    body = r.text

    evidence_lines: list[str] = [f"GET {url} → HTTP {r.status_code}"]

    # ── Gate 1: must be HTML ─────────────────────────────────────────────────
    if "text/html" not in content_type:
        logger.debug(f"clickjacking: skipping {url} — not HTML ({content_type})")
        return None

    # ── Gate 2: X-Frame-Options ──────────────────────────────────────────────
    xfo = headers.get("x-frame-options", "")
    if xfo.strip().upper() in ("DENY", "SAMEORIGIN"):
        logger.debug(f"clickjacking: protected by X-Frame-Options: {xfo}")
        return None
    evidence_lines.append(f"X-Frame-Options: {xfo or '(absent)'}")

    # ── Gate 3: CSP frame-ancestors ──────────────────────────────────────────
    csp = headers.get("content-security-policy", "")
    if "frame-ancestors" in csp.lower():
        fa = re.search(r"frame-ancestors\s+([^;]+)", csp, re.I)
        directive = fa.group(1).strip() if fa else csp
        if "'none'" in directive or ("'self'" in directive and "*" not in directive):
            logger.debug(f"clickjacking: protected by CSP frame-ancestors: {directive}")
            return None
    evidence_lines.append(f"Content-Security-Policy frame-ancestors: {csp or '(absent)'}")

    # ── Gate 4: non-trivial body ──────────────────────────────────────────────
    if len(body.strip()) < 200:
        logger.debug(f"clickjacking: body too small to be meaningful ({len(body)} bytes)")
        return None

    # ── Gate 5: JS frame-busting (degrades confidence, doesn't block) ────────
    framebusting_found = any(
        re.search(pat, body, re.I) for pat in _FRAMEBUSTING_PATTERNS
    )
    confidence = 0.75 if framebusting_found else 0.95
    if framebusting_found:
        evidence_lines.append("JS frame-busting code detected (reduces confidence)")

    evidence = "\n".join(evidence_lines)
    proof = Proof(
        verified=True,
        method="header_analysis + body_inspection",
        request=f"GET {url}",
        response=evidence,
    )

    return Finding(
        title="Clickjacking vulnerability confirmed",
        severity=Severity.MEDIUM,
        category=FindingCategory.WEB,
        source="verify.clickjacking",
        target=url,
        description=(
            "The page can be embedded in an attacker-controlled <iframe>. "
            "Neither X-Frame-Options nor a restrictive CSP frame-ancestors directive "
            "is present. An attacker can overlay a transparent iframe over a legitimate "
            "UI to trick users into performing unintended actions."
        ),
        remediation=(
            "Add either:\n"
            "  X-Frame-Options: DENY\n"
            "or a Content-Security-Policy header with:\n"
            "  frame-ancestors 'none'\n"
            "CSP frame-ancestors is preferred as it supersedes X-Frame-Options."
        ),
        confidence=confidence,
        cvss=_CVSS,
        proof=proof,
        references=[
            "https://owasp.org/www-community/attacks/Clickjacking",
            "https://cheatsheetseries.owasp.org/cheatsheets/Clickjacking_Defense_Cheat_Sheet.html",
        ],
    )
