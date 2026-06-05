"""Web scan skill — HTTP security header analysis + basic response inspection."""

from __future__ import annotations

import logging

import requests

from config import API_TIMEOUT
from core.context import Context
from core.models import Finding, Severity, FindingCategory

logger = logging.getLogger(__name__)

# (header, title, severity, description, remediation, reference)
SECURITY_HEADERS = [
    (
        "Strict-Transport-Security",
        "Missing HTTP Strict Transport Security (HSTS)",
        Severity.MEDIUM,
        "Without HSTS, browsers may downgrade HTTPS connections to HTTP, enabling SSL stripping.",
        "Add: Strict-Transport-Security: max-age=31536000; includeSubDomains; preload",
        "https://owasp.org/www-project-secure-headers/#http-strict-transport-security",
    ),
    (
        "X-Frame-Options",
        "Missing X-Frame-Options — clickjacking risk",
        Severity.MEDIUM,
        "The page can be embedded in an iframe on an attacker-controlled site.",
        "Add: X-Frame-Options: DENY  (or use Content-Security-Policy: frame-ancestors 'none')",
        "https://owasp.org/www-project-secure-headers/#x-frame-options",
    ),
    (
        "X-Content-Type-Options",
        "Missing X-Content-Type-Options",
        Severity.LOW,
        "Browsers may MIME-sniff responses, enabling content injection attacks.",
        "Add: X-Content-Type-Options: nosniff",
        "https://owasp.org/www-project-secure-headers/#x-content-type-options",
    ),
    (
        "Content-Security-Policy",
        "Missing Content-Security-Policy",
        Severity.MEDIUM,
        "No CSP means XSS payloads can load arbitrary scripts from any origin.",
        "Define a strict CSP; at minimum: Content-Security-Policy: default-src 'self'",
        "https://owasp.org/www-project-secure-headers/#content-security-policy",
    ),
    (
        "Referrer-Policy",
        "Missing Referrer-Policy",
        Severity.LOW,
        "Full URL may be sent in the Referer header to third parties.",
        "Add: Referrer-Policy: strict-origin-when-cross-origin",
        "https://owasp.org/www-project-secure-headers/#referrer-policy",
    ),
    (
        "Permissions-Policy",
        "Missing Permissions-Policy",
        Severity.LOW,
        "Browser features (camera, geolocation, etc.) are not explicitly restricted.",
        "Add: Permissions-Policy: geolocation=(), camera=(), microphone=()",
        "https://owasp.org/www-project-secure-headers/#permissions-policy",
    ),
]


def _scan_target(url: str, context: Context) -> None:
    try:
        r = requests.get(url, timeout=API_TIMEOUT, allow_redirects=True)
    except Exception as e:
        logger.warning(f"HTTP probe failed for {url}: {e}")
        context.add_error("web_scan", str(e))
        return

    headers = {k.lower(): v for k, v in r.headers.items()}

    # 1. Security headers
    for header, title, severity, desc, rem, ref in SECURITY_HEADERS:
        if header.lower() not in headers:
            context.add_finding(Finding(
                title=title,
                severity=severity,
                category=FindingCategory.WEB,
                source="header_scan",
                target=url,
                description=desc,
                remediation=rem,
                confidence=0.95,
                references=[ref],
            ))

    # 2. Server version disclosure
    server = headers.get("server", "")
    if server:
        context.add_finding(Finding(
            title=f"Web server version disclosed: {server}",
            severity=Severity.LOW,
            category=FindingCategory.INFO_LEAK,
            source="header_scan",
            target=url,
            description=f"The Server header reveals '{server}', enabling targeted CVE searches.",
            remediation="Configure the server to omit or genericise the Server header.",
            confidence=0.95,
            evidence=f"Server: {server}",
        ))

    # 3. Technology stack disclosure
    x_powered = headers.get("x-powered-by", "")
    if x_powered:
        context.add_finding(Finding(
            title=f"Technology stack disclosed via X-Powered-By: {x_powered}",
            severity=Severity.LOW,
            category=FindingCategory.INFO_LEAK,
            source="header_scan",
            target=url,
            description=f"X-Powered-By reveals '{x_powered}', narrowing attacker focus.",
            remediation="Remove the X-Powered-By header (e.g. expose_php=Off in php.ini).",
            confidence=0.95,
            evidence=f"X-Powered-By: {x_powered}",
        ))

    # 4. HTTP → HTTPS redirect enforcement
    if url.startswith("http://"):
        try:
            r2 = requests.get(url, timeout=API_TIMEOUT, allow_redirects=False)
            loc = r2.headers.get("Location", "")
            if r2.status_code not in (301, 302) or not loc.startswith("https"):
                context.add_finding(Finding(
                    title="HTTP requests not redirected to HTTPS",
                    severity=Severity.MEDIUM,
                    category=FindingCategory.CRYPTO,
                    source="header_scan",
                    target=url,
                    description="HTTP connections are accepted without redirecting to HTTPS.",
                    remediation="Add a 301 redirect from http:// to https:// at the web server level.",
                    confidence=0.9,
                    references=["https://owasp.org/www-project-web-security-testing-guide/"],
                ))
        except Exception:
            pass

    # 5. Cookie flags
    for cookie in r.cookies:
        if not cookie.secure:
            context.add_finding(Finding(
                title=f"Cookie '{cookie.name}' missing Secure flag",
                severity=Severity.MEDIUM,
                category=FindingCategory.WEB,
                source="header_scan",
                target=url,
                description="Cookie can be transmitted over unencrypted HTTP connections.",
                remediation=f"Set the Secure attribute on the '{cookie.name}' cookie.",
                confidence=0.9,
                evidence=f"Set-Cookie: {cookie.name}=...",
            ))
        if not cookie.has_nonstandard_attr("HttpOnly"):
            context.add_finding(Finding(
                title=f"Cookie '{cookie.name}' missing HttpOnly flag",
                severity=Severity.MEDIUM,
                category=FindingCategory.WEB,
                source="header_scan",
                target=url,
                description="Cookie is accessible via JavaScript, increasing XSS impact.",
                remediation=f"Set the HttpOnly attribute on the '{cookie.name}' cookie.",
                confidence=0.9,
                evidence=f"Set-Cookie: {cookie.name}=...",
            ))

    logger.info(f"web_scan: {len(context.findings)} findings after scanning {url}")


def run(context: Context) -> Context:
    logger.info(f"Starting web scan on {context.target}")

    if context.tool_status.get("nikto"):
        try:
            from tools.nikto import run_nikto
            raw = run_nikto(context.target)
            for item in (raw or []):
                context.add_finding(Finding(
                    title=item,
                    severity=Severity.MEDIUM,
                    category=FindingCategory.WEB,
                    source="nikto",
                    target=context.target,
                    confidence=0.7,
                ))
            logger.info(f"nikto: {len(raw or [])} issues")
            return context
        except Exception as e:
            logger.warning(f"nikto failed: {e}")
            context.add_error("web_scan", str(e))

    # HTTP fallback — scan services found in exposure + original target
    targets = [svc.split(" ")[0] for svc in context.services if "http" in svc.lower()]
    if not targets:
        raw = context.target.rstrip("/")
        targets = [f"https://{raw}" if not raw.startswith("http") else raw]

    for t in targets[:3]:
        _scan_target(t, context)

    return context


skill = {"name": "web_scan", "run": run}
