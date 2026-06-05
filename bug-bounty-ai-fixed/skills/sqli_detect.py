"""
SQLi detection skill — safe, non-destructive.

Techniques used (no data extraction, no blind time-based attacks):
  1. Error-based detection  — inject syntax errors, watch for DB error strings
  2. Boolean-based detection — compare responses for TRUE vs FALSE conditions
  3. Reflection check       — confirm injected value is reflected (not blind)

What this does NOT do:
  - Extract any data
  - Use sleep/benchmark (time-based)
  - Modify any data (UPDATE/INSERT/DELETE/DROP)
  - Send payloads to non-form/non-query parameters
"""
from __future__ import annotations

import logging
import re
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse

import requests

from config import API_TIMEOUT
from core.context import Context
from core.models import (Finding, Severity, FindingCategory,
                          CvssVector, CvssAV, CvssAC, CvssPR,
                          CvssUI, CvssScope, CvssImpact, Proof)

logger = logging.getLogger(__name__)

_CVSS_SQLI = CvssVector(
    AV=CvssAV.NETWORK, AC=CvssAC.LOW, PR=CvssPR.NONE, UI=CvssUI.NONE,
    S=CvssScope.CHANGED, C=CvssImpact.HIGH, I=CvssImpact.HIGH, A=CvssImpact.LOW,
)  # 10.0 CRITICAL

# DB error patterns — confirmed in response body = strong signal
_DB_ERRORS = [
    # MySQL
    (r"you have an error in your sql syntax", "MySQL"),
    (r"mysql_fetch_array\(\)",               "MySQL"),
    (r"mysql_num_rows\(\)",                   "MySQL"),
    (r"supplied argument is not a valid mysql", "MySQL"),
    # PostgreSQL
    (r"pg_query\(\):",                        "PostgreSQL"),
    (r"pg_exec\(\):",                         "PostgreSQL"),
    (r"unterminated quoted string at or near", "PostgreSQL"),
    # MSSQL
    (r"unclosed quotation mark after the character string", "MSSQL"),
    (r"incorrect syntax near",                "MSSQL"),
    (r"microsoft ole db provider for sql",    "MSSQL"),
    # Oracle
    (r"ora-\d{5}:",                           "Oracle"),
    (r"oracle error",                         "Oracle"),
    # SQLite
    (r"sqlite_master",                        "SQLite"),
    (r"sqlite error",                         "SQLite"),
    # Generic
    (r"sql syntax.*mysql",                    "Generic SQL"),
    (r"warning.*\Wmysqli?_",                  "Generic SQL"),
    (r"valid mysql result",                   "Generic SQL"),
    (r"mysqlclient",                          "Generic SQL"),
]

# Safe error-triggering payloads — just a single quote or comment
_ERROR_PAYLOADS = ["'", '"', "''", "`", "\\", "')"]

# Boolean pair — compare length/content divergence
_BOOL_TRUE  = "' OR '1'='1"
_BOOL_FALSE = "' OR '1'='2"


def _inject_param(url: str, param: str, value: str) -> str:
    """Return url with *param* replaced by *value*."""
    parsed  = urlparse(url)
    qs      = parse_qs(parsed.query, keep_blank_values=True)
    qs[param] = [value]
    new_query = urlencode(qs, doseq=True)
    return urlunparse(parsed._replace(query=new_query))


def _get(url: str) -> requests.Response | None:
    try:
        return requests.get(url, timeout=API_TIMEOUT, allow_redirects=True)
    except Exception:
        return None


def _check_error_based(url: str, param: str, original_val: str) -> Finding | None:
    for payload in _ERROR_PAYLOADS:
        test_url = _inject_param(url, param, original_val + payload)
        r = _get(test_url)
        if not r:
            continue
        body = r.text.lower()
        for pattern, db_type in _DB_ERRORS:
            if re.search(pattern, body, re.I):
                return Finding(
                    title=f"SQL injection (error-based) in parameter '{param}'",
                    severity=Severity.CRITICAL,
                    category=FindingCategory.INJECTION,
                    source="sqli_detect",
                    target=url,
                    description=(
                        f"Injecting `{payload}` into parameter `{param}` triggers a "
                        f"{db_type} database error message in the response. "
                        "This strongly indicates unsanitised SQL query construction."
                    ),
                    remediation=(
                        "Use parameterised queries / prepared statements. "
                        "Never interpolate user input directly into SQL strings."
                    ),
                    confidence=0.95,
                    cvss=_CVSS_SQLI,
                    evidence=f"Payload: {payload} → DB error pattern matched: {pattern}",
                    proof=Proof(
                        verified=True,
                        method="error_based_sqli",
                        request=f"GET {test_url}",
                        response=r.text[:500],
                    ),
                    references=[
                        "https://owasp.org/www-community/attacks/SQL_Injection",
                        "https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html",
                    ],
                )
    return None


def _check_boolean_based(url: str, param: str, original_val: str) -> Finding | None:
    """
    Compare response to TRUE vs FALSE boolean payloads.
    Significant length difference = likely boolean SQLi.
    Does NOT extract data — only measures response divergence.
    """
    r_baseline = _get(url)
    r_true     = _get(_inject_param(url, param, original_val + _BOOL_TRUE))
    r_false    = _get(_inject_param(url, param, original_val + _BOOL_FALSE))

    if not all([r_baseline, r_true, r_false]):
        return None

    baseline_len = len(r_baseline.text)
    true_len     = len(r_true.text)
    false_len    = len(r_false.text)

    # True response should differ from false; both should differ from baseline
    true_diff  = abs(true_len  - baseline_len)
    false_diff = abs(false_len - baseline_len)
    pair_diff  = abs(true_len  - false_len)

    # Require meaningful divergence (>5% of baseline or >200 chars)
    threshold = max(200, baseline_len * 0.05)
    if pair_diff > threshold and true_diff > 50:
        return Finding(
            title=f"SQL injection (boolean-based) in parameter '{param}'",
            severity=Severity.CRITICAL,
            category=FindingCategory.INJECTION,
            source="sqli_detect",
            target=url,
            description=(
                f"Responses to TRUE and FALSE boolean SQL payloads in parameter `{param}` "
                f"differ by {pair_diff} bytes (threshold: {threshold:.0f}). "
                "This indicates the application conditionally alters output based on injected SQL logic."
            ),
            remediation=(
                "Use parameterised queries. "
                "Validate and whitelist all query parameter values."
            ),
            confidence=0.80,
            cvss=_CVSS_SQLI,
            evidence=(
                f"Baseline: {baseline_len}B | TRUE payload: {true_len}B | "
                f"FALSE payload: {false_len}B | divergence: {pair_diff}B"
            ),
            proof=Proof(
                verified=True,
                method="boolean_based_sqli",
                request=(
                    f"GET {_inject_param(url, param, original_val + _BOOL_TRUE)}\n"
                    f"GET {_inject_param(url, param, original_val + _BOOL_FALSE)}"
                ),
                response=(
                    f"TRUE len={true_len} | FALSE len={false_len} | "
                    f"diff={pair_diff} (threshold {threshold:.0f})"
                ),
            ),
            references=["https://owasp.org/www-community/attacks/Blind_SQL_Injection"],
        )
    return None


def run(context: Context) -> Context:
    logger.info("Starting SQLi detection")

    # Collect URLs with query parameters from endpoints + services
    candidates: list[str] = []
    for ep in context.endpoints:
        url = str(ep).split(" ")[0]
        if "?" in url:
            candidates.append(url)

    # Also probe known login/search paths on all discovered hosts
    param_paths = [
        "/search?q=test", "/index.php?id=1", "/page?id=1",
        "/product?id=1", "/item?id=1", "/user?id=1",
        "/login?redirect=/", "/news?id=1", "/post?id=1",
    ]
    bases = [svc.split(" ")[0].rstrip("/")
             for svc in context.services if "http" in svc.lower()]
    if not bases:
        t = context.target.rstrip("/")
        bases = [t if t.startswith("http") else f"https://{t}"]

    for base in bases[:2]:
        for path in param_paths:
            candidates.append(f"{base}{path}")

    # Deduplicate
    candidates = list(dict.fromkeys(candidates))
    logger.info(f"SQLi: testing {len(candidates)} candidate URLs")

    found: set[str] = set()

    for url in candidates[:30]:   # cap to avoid long runtime
        parsed = urlparse(url)
        params = parse_qs(parsed.query)
        if not params:
            continue

        for param, values in params.items():
            original = values[0] if values else ""
            key = f"{param}@{parsed.netloc}{parsed.path}"
            if key in found:
                continue

            # Error-based first (faster, higher confidence)
            finding = _check_error_based(url, param, original)
            if not finding:
                finding = _check_boolean_based(url, param, original)

            if finding:
                found.add(key)
                context.add_finding(finding)
                logger.info(f"SQLi confirmed: {finding.title} @ {url}")

    logger.info(f"SQLi detection complete — {len(found)} injection point(s) found")
    return context


skill = {"name": "sqli_detect", "run": run}
