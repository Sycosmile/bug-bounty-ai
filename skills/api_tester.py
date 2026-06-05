"""API tester skill — probe discovered endpoints for runtime vulnerabilities."""

from __future__ import annotations

import logging

import requests

from config import API_TIMEOUT
from core.context import Context
from core.models import Finding, Severity, FindingCategory

logger = logging.getLogger(__name__)

_HEADERS = {"User-Agent": "Mozilla/5.0 (compatible; bug-bounty-ai/1.0)"}

_DEBUG_PATTERNS = [
    "traceback", "stack trace", "exception in", "fatal error",
    "sql syntax", "mysql_fetch", "pg_query", "odbc_",
    "undefined index", "undefined variable", "warning:", "notice:",
    "debug mode", "you have an error in your sql",
]

_SENSITIVE_RESPONSE_PATTERNS = [
    ("password",   "Response body may contain plaintext passwords"),
    ("secret",     "Response body may contain secret values"),
    ("api_key",    "Response body may contain API keys"),
    ("access_token", "Response body may contain access tokens"),
    ("private_key", "Response body may contain private key material"),
]


def _url(endpoint) -> str:
    return str(endpoint).split(" ")[0] if isinstance(endpoint, str) else ""


def run(context: Context) -> Context:
    if not context.endpoints:
        logger.info("No endpoints to test")
        return context

    logger.info(f"Testing {len(context.endpoints)} endpoints")
    initial_count = len(context.findings)

    for ep in context.endpoints:
        url = _url(ep)
        if not url or not url.startswith("http"):
            continue

        try:
            r_get  = requests.get(url,  timeout=API_TIMEOUT, headers=_HEADERS, allow_redirects=True)
            r_post = requests.post(url, timeout=API_TIMEOUT, headers={**_HEADERS, "Content-Type": "application/json"},
                                   data="{}", allow_redirects=False)
        except requests.exceptions.RequestException:
            continue

        body = r_get.text.lower()
        path = url.split("://", 1)[-1].split("/", 1)[-1] if "/" in url else ""

        # 1. Debug / error information leaked
        matched = [p for p in _DEBUG_PATTERNS if p in body]
        if matched:
            context.add_finding(Finding(
                title="Debug or error information leaked in HTTP response",
                severity=Severity.HIGH,
                category=FindingCategory.INFO_LEAK,
                source="api_tester",
                target=url,
                description=f"Response body contains debug markers: {', '.join(matched[:3])}",
                remediation="Disable debug mode in production; use generic error pages.",
                confidence=0.85,
                evidence=f"Matched patterns: {matched[:3]}",
            ))

        # 2. Sensitive data in response body
        for pattern, title in _SENSITIVE_RESPONSE_PATTERNS:
            if pattern in body:
                context.add_finding(Finding(
                    title=title,
                    severity=Severity.HIGH,
                    category=FindingCategory.INFO_LEAK,
                    source="api_tester",
                    target=url,
                    description=f"Keyword '{pattern}' found in the response body.",
                    remediation="Audit the endpoint response; remove sensitive data from API output.",
                    confidence=0.7,
                    evidence=f"Keyword '{pattern}' present in response",
                ))
                break  # one finding per endpoint for this class

        # 3. Unauthenticated 200 on sensitive paths
        if r_get.status_code == 200 and any(
            x in path.lower() for x in ["admin", "config", "users", "account", "profile", "manage"]
        ):
            context.add_finding(Finding(
                title=f"Sensitive endpoint accessible without authentication: /{path}",
                severity=Severity.HIGH,
                category=FindingCategory.AUTH,
                source="api_tester",
                target=url,
                description="The endpoint returned HTTP 200 without any authentication.",
                remediation="Enforce authentication and authorisation on all sensitive endpoints.",
                confidence=0.75,
                evidence=f"GET {url} → HTTP {r_get.status_code}",
            ))

        # 4. 500 on POST — potential injection / parsing surface
        if r_post.status_code == 500:
            context.add_finding(Finding(
                title="Server error (HTTP 500) triggered by POST request",
                severity=Severity.MEDIUM,
                category=FindingCategory.INJECTION,
                source="api_tester",
                target=url,
                description="POST with empty JSON body caused a 500 response — possible input handling flaw.",
                remediation="Implement robust input validation; never expose internal errors to clients.",
                confidence=0.65,
                evidence=f"POST {url} with empty JSON → HTTP 500",
            ))

        # 5. Wildcard CORS
        acao = r_get.headers.get("Access-Control-Allow-Origin", "")
        if acao.strip() == "*":
            context.add_finding(Finding(
                title="Wildcard CORS policy (Access-Control-Allow-Origin: *)",
                severity=Severity.MEDIUM,
                category=FindingCategory.WEB,
                source="api_tester",
                target=url,
                description="Any origin can make credentialed cross-origin requests to this endpoint.",
                remediation="Replace wildcard with an explicit allowlist of trusted origins.",
                confidence=0.95,
                evidence="Access-Control-Allow-Origin: *",
                references=["https://owasp.org/www-project-web-security-testing-guide/"],
            ))

        # 6. Missing auth on API paths that returned data
        if r_get.status_code == 200 and "/api/" in url.lower() and len(r_get.content) > 100:
            context.add_finding(Finding(
                title="API endpoint returns data without authentication",
                severity=Severity.MEDIUM,
                category=FindingCategory.AUTH,
                source="api_tester",
                target=url,
                description="API endpoint returned a non-empty response without any auth header.",
                remediation="Enforce token-based authentication on all API endpoints.",
                confidence=0.65,
                evidence=f"GET {url} → {r_get.status_code}, {len(r_get.content)} bytes",
            ))

    new = len(context.findings) - initial_count
    logger.info(f"api_tester: {new} new findings")
    return context


skill = {"name": "api_tester", "run": run}
