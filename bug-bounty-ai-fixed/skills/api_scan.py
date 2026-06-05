"""API scan skill — endpoint discovery and sensitive path detection."""

from __future__ import annotations

import logging
from typing import Optional

import requests

from config import API_TIMEOUT, API_TEST_ENDPOINTS
from core.context import Context
from core.models import Finding, Severity, FindingCategory

logger = logging.getLogger(__name__)

# (path, title, severity, category, description, remediation)
SENSITIVE_PATHS: list[tuple[str, str, Severity, FindingCategory, str, str]] = [
    ("/.env",             "Environment file publicly accessible",        Severity.CRITICAL, FindingCategory.MISCONFIGURED,
     ".env files contain credentials, API keys, and database URLs.",
     "Block access to .env via web server config; never commit .env to the repo."),

    ("/backup.zip",       "Backup archive publicly accessible",          Severity.CRITICAL, FindingCategory.MISCONFIGURED,
     "Backup archives may contain source code, credentials, and database dumps.",
     "Remove backup files from the web root; use off-site backup storage."),

    ("/db.sql",           "Database dump publicly accessible",           Severity.CRITICAL, FindingCategory.MISCONFIGURED,
     "SQL dumps expose the entire database schema and potentially PII/credentials.",
     "Remove database dumps from the web root immediately."),

    ("/config.php",       "PHP config file publicly accessible",         Severity.CRITICAL, FindingCategory.MISCONFIGURED,
     "Config files may contain database credentials and secret keys.",
     "Move config files outside the web root or block via web server rules."),

    ("/graphiql",         "GraphQL explorer publicly accessible",        Severity.MEDIUM,   FindingCategory.API,
     "GraphiQL lets anyone introspect the schema and craft arbitrary queries.",
     "Disable GraphiQL in production or restrict to authenticated users."),

    ("/graphql",          "GraphQL endpoint reachable",                  Severity.LOW,      FindingCategory.API,
     "GraphQL endpoint is publicly reachable; introspection may be enabled.",
     "Disable introspection in production; apply query depth/complexity limits."),

    ("/swagger-ui.html",  "Swagger UI publicly accessible",              Severity.MEDIUM,   FindingCategory.API,
     "Swagger UI exposes full API documentation including auth requirements.",
     "Restrict Swagger UI to internal networks or authenticated sessions."),

    ("/swagger",          "Swagger endpoint reachable",                  Severity.LOW,      FindingCategory.API,
     "Swagger/OpenAPI spec is publicly available.",
     "Restrict API docs to authenticated users in production."),

    ("/openapi.json",     "OpenAPI specification publicly accessible",   Severity.LOW,      FindingCategory.API,
     "Full API schema is exposed, aiding targeted attack planning.",
     "Restrict access to the OpenAPI spec in production environments."),

    ("/api-docs",         "API documentation publicly accessible",       Severity.LOW,      FindingCategory.API,
     "API documentation is publicly reachable.",
     "Restrict to authenticated sessions or internal networks."),

    ("/wp-admin",         "WordPress admin panel accessible",            Severity.HIGH,     FindingCategory.AUTH,
     "The WordPress admin panel is reachable from the internet.",
     "Restrict /wp-admin by IP address or implement two-factor authentication."),

    ("/wp-login.php",     "WordPress login page exposed",                Severity.MEDIUM,   FindingCategory.AUTH,
     "Exposed login page enables brute-force and credential-stuffing attacks.",
     "Use a login protection plugin; restrict by IP; enforce MFA."),

    ("/admin",            "Admin panel accessible",                      Severity.HIGH,     FindingCategory.AUTH,
     "An admin interface is reachable from the internet.",
     "Restrict admin interfaces to internal networks or VPN."),

    ("/administrator",    "Administrator panel accessible",              Severity.HIGH,     FindingCategory.AUTH,
     "An administrator interface is reachable from the internet.",
     "Restrict to VPN or internal networks; enforce MFA."),

    ("/phpmyadmin",       "phpMyAdmin publicly accessible",              Severity.CRITICAL, FindingCategory.AUTH,
     "phpMyAdmin exposes full database management to the internet.",
     "Remove phpMyAdmin from the web root or restrict to localhost only."),

    ("/robots.txt",       "robots.txt reveals hidden paths",             Severity.INFO,     FindingCategory.RECON,
     "robots.txt may disclose internal paths not intended for public access.",
     "Audit robots.txt; avoid listing sensitive paths."),

    ("/sitemap.xml",      "sitemap.xml accessible",                      Severity.INFO,     FindingCategory.RECON,
     "Sitemap enumerates URLs and may reveal internal structure.",
     "Review sitemap for unintentionally exposed paths."),

    ("/server-status",    "Apache server-status page exposed",           Severity.HIGH,     FindingCategory.MISCONFIGURED,
     "Exposes real-time request data, internal IPs, and worker state.",
     "Restrict mod_status to localhost: Allow from 127.0.0.1"),

    ("/.git/HEAD",        "Git repository exposed",                      Severity.CRITICAL, FindingCategory.MISCONFIGURED,
     "The .git directory is publicly accessible; source code can be reconstructed.",
     "Block /.git in web server config; never deploy with .git in the web root."),

    ("/health",           "Health/status endpoint accessible",           Severity.INFO,     FindingCategory.API,
     "Health endpoint may expose internal component status.",
     "Restrict health endpoints to monitoring infrastructure."),

    ("/metrics",          "Metrics endpoint accessible",                 Severity.MEDIUM,   FindingCategory.MISCONFIGURED,
     "Prometheus/metrics endpoints expose internal performance and configuration data.",
     "Restrict metrics endpoint to internal networks or monitoring systems."),
]

EXTRA_PATHS = [p for p, *_ in SENSITIVE_PATHS] + list(API_TEST_ENDPOINTS)


def _base_url(target: str) -> str:
    t = target.rstrip("/")
    if not t.startswith("http"):
        t = f"http://{t}"
    return t


def _probe(url: str) -> Optional[tuple[int, int]]:
    """Returns (status_code, content_length) or None on error."""
    try:
        r = requests.get(url, timeout=API_TIMEOUT, allow_redirects=False)
        return r.status_code, len(r.content)
    except Exception:
        return None


def run(context: Context) -> Context:
    logger.info(f"Starting API scan on {context.target}")

    bases = [svc.split(" ")[0].rstrip("/")
             for svc in context.services if "http" in svc.lower()]
    if not bases:
        bases = [_base_url(context.target)]

    seen_paths: set[str] = set()

    for base in bases[:3]:
        for path, title, severity, category, desc, rem in SENSITIVE_PATHS:
            if path in seen_paths:
                continue

            url = f"{base}{path}"
            result = _probe(url)
            if result is None:
                continue

            status, length = result
            entry = f"{url} [{status}]"

            if status in (200, 301, 302, 401, 403):
                if entry not in context.endpoints:
                    context.endpoints.append(entry)

                # Only raise findings for interesting responses
                if status in (200, 401, 403) and severity != Severity.INFO:
                    # 401/403 still confirms the path exists — worth noting
                    effective_severity = severity
                    if status in (401, 403) and severity in (Severity.CRITICAL, Severity.HIGH):
                        effective_severity = Severity.MEDIUM

                    context.add_finding(Finding(
                        title=title,
                        severity=effective_severity,
                        category=category,
                        source="api_scan",
                        target=url,
                        description=desc,
                        remediation=rem,
                        confidence=0.85 if status == 200 else 0.7,
                        evidence=f"HTTP {status}, {length} bytes",
                    ))
                    seen_paths.add(path)

    logger.info(f"api_scan: {len(context.endpoints)} endpoints, findings so far: {len(context.findings)}")
    return context


skill = {"name": "api_scan", "run": run}
