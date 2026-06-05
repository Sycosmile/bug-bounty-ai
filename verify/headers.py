"""
Header verification — re-checks each security-header finding with a live
request to confirm the header is genuinely absent (not a false positive).
"""
from __future__ import annotations
import logging
import requests
from config import API_TIMEOUT
from core.models import Finding, Proof

logger = logging.getLogger(__name__)

_HEADER_MAP = {
    "strict-transport-security": "Strict-Transport-Security",
    "x-frame-options":           "X-Frame-Options",
    "x-content-type-options":    "X-Content-Type-Options",
    "content-security-policy":   "Content-Security-Policy",
    "referrer-policy":           "Referrer-Policy",
    "permissions-policy":        "Permissions-Policy",
}

def verify(finding: Finding) -> Finding | None:
    try:
        r = requests.get(finding.target, timeout=API_TIMEOUT, allow_redirects=True)
    except Exception as e:
        logger.debug(f"headers.verify failed for {finding.target}: {e}")
        return None

    headers = {k.lower(): v for k, v in r.headers.items()}
    title_lower = finding.title.lower()

    for key, canonical in _HEADER_MAP.items():
        if key in title_lower:
            if key not in headers:
                finding.proof = Proof(
                    verified=True,
                    method="live_header_check",
                    request=f"GET {finding.target}",
                    response=f"HTTP {r.status_code} — {canonical}: (absent)\n"
                             f"All response headers: {dict(r.headers)}",
                )
                return finding
            else:
                logger.debug(f"headers.verify: {canonical} IS present — dropping finding")
                return None
    return None
