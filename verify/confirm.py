"""
Exploit confirmation engine — safe, non-destructive verification.

Each verifier takes a Finding and a Context, attempts safe confirmation,
and returns the same Finding with proof.verified=True and proof populated,
or None if confirmation failed / was skipped.

Verifiers included
------------------
  cors_wildcard       — confirms CORS * policy is exploitable cross-origin
  open_redirect       — confirms redirect follows attacker-supplied URL
  directory_listing   — confirms directory listing is enabled
  sensitive_file      — confirms sensitive file is readable (checks body content)
  error_disclosure    — confirms debug/stack-trace content in response
  http_no_redirect    — confirms HTTP does NOT redirect to HTTPS
  hsts_missing        — confirms HSTS header is absent on HTTPS endpoint
  unauth_endpoint     — confirms endpoint returns data without auth header
  options_method      — confirms dangerous HTTP methods are allowed
  git_exposure        — confirms .git/HEAD is readable and looks like a repo
"""

from __future__ import annotations

import logging
import re
from typing import Optional, Callable

import requests

from config import API_TIMEOUT
from core.models import (
    Finding, FindingCategory, Proof,
    CvssVector, CvssAV, CvssAC, CvssPR, CvssUI, CvssScope, CvssImpact,
)
from core.context import Context

logger = logging.getLogger(__name__)

VerifierFn = Callable[[Finding, Context], Optional[Finding]]


# ─────────────────────────────────────────────────────────────────────────────
# helpers
# ─────────────────────────────────────────────────────────────────────────────

def _get(url: str, **kwargs) -> Optional[requests.Response]:
    try:
        return requests.get(url, timeout=API_TIMEOUT, allow_redirects=False, **kwargs)
    except Exception as e:
        logger.debug(f"confirm._get failed {url}: {e}")
        return None


def _attach_proof(finding: Finding, method: str, request: str, response: str) -> Finding:
    finding.proof = Proof(
        verified=True,
        method=method,
        request=request,
        response=response[:2000],
    )
    return finding


# ─────────────────────────────────────────────────────────────────────────────
# individual verifiers
# ─────────────────────────────────────────────────────────────────────────────

def cors_wildcard(finding: Finding, ctx: Context) -> Optional[Finding]:
    r = _get(finding.target, headers={"Origin": "https://evil.example.com"})
    if not r:
        return None
    acao = r.headers.get("Access-Control-Allow-Origin", "")
    acac = r.headers.get("Access-Control-Allow-Credentials", "")
    if acao.strip() == "*":
        return _attach_proof(finding,
            method="cors_probe",
            request=f"GET {finding.target}\nOrigin: https://evil.example.com",
            response=f"Access-Control-Allow-Origin: {acao}\nAccess-Control-Allow-Credentials: {acac}",
        )
    return None


def open_redirect(finding: Finding, ctx: Context) -> Optional[Finding]:
    payload = "https://evil.example.com"
    for param in ("url", "redirect", "next", "return", "to", "dest", "location"):
        test_url = f"{finding.target}?{param}={payload}"
        r = _get(test_url)
        if not r:
            continue
        loc = r.headers.get("Location", "")
        if r.status_code in (301, 302, 303, 307, 308) and "evil.example.com" in loc:
            return _attach_proof(finding,
                method="open_redirect_probe",
                request=f"GET {test_url}",
                response=f"HTTP {r.status_code}\nLocation: {loc}",
            )
    return None


def directory_listing(finding: Finding, ctx: Context) -> Optional[Finding]:
    r = _get(finding.target)
    if not r:
        return None
    body = r.text.lower()
    if r.status_code == 200 and any(
        marker in body for marker in
        ["index of /", "directory listing", "parent directory", "[dir]", "[parentdir]"]
    ):
        snippet = body[:500].replace("\n", " ")
        return _attach_proof(finding,
            method="directory_listing_check",
            request=f"GET {finding.target}",
            response=f"HTTP 200\nBody snippet: {snippet}",
        )
    return None


def sensitive_file(finding: Finding, ctx: Context) -> Optional[Finding]:
    r = _get(finding.target)
    if not r or r.status_code != 200:
        return None
    body = r.text
    # Confirm content actually looks sensitive
    indicators = {
        ".env":       [r"(?i)(DB_PASSWORD|APP_KEY|SECRET|API_KEY)\s*=\s*\S+"],
        ".git/HEAD":  [r"ref:\s*refs/heads/"],
        "backup":     [r"(?i)(CREATE TABLE|INSERT INTO|mysqldump)"],
        "config":     [r"(?i)(password|secret|token)\s*[=:]\s*['\"]?\S+"],
    }
    path = finding.target.lower()
    for key, patterns in indicators.items():
        if key in path:
            for pat in patterns:
                m = re.search(pat, body)
                if m:
                    return _attach_proof(finding,
                        method="sensitive_content_check",
                        request=f"GET {finding.target}",
                        response=f"HTTP 200\nMatched pattern: {pat}\nSnippet: {body[:300]}",
                    )
    # Generic: 200 + non-empty
    if len(body.strip()) > 50:
        return _attach_proof(finding,
            method="sensitive_file_accessible",
            request=f"GET {finding.target}",
            response=f"HTTP 200, {len(body)} bytes",
        )
    return None


def error_disclosure(finding: Finding, ctx: Context) -> Optional[Finding]:
    r = _get(finding.target)
    if not r:
        return None
    body = r.text.lower()
    patterns = ["traceback", "stack trace", "exception in", "fatal error",
                "sql syntax", "mysql_fetch", "you have an error in your sql"]
    matched = [p for p in patterns if p in body]
    if matched:
        return _attach_proof(finding,
            method="error_body_scan",
            request=f"GET {finding.target}",
            response=f"HTTP {r.status_code}\nMatched: {matched}\nSnippet: {r.text[:300]}",
        )
    return None


def http_no_redirect(finding: Finding, ctx: Context) -> Optional[Finding]:
    url = finding.target
    if not url.startswith("http://"):
        url = f"http://{url.split('://', 1)[-1]}"
    r = _get(url)
    if not r:
        return None
    loc = r.headers.get("Location", "")
    if r.status_code not in (301, 302) or not loc.startswith("https"):
        return _attach_proof(finding,
            method="http_redirect_check",
            request=f"GET {url}",
            response=f"HTTP {r.status_code}\nLocation: {loc or '(none)'}",
        )
    return None


def hsts_missing(finding: Finding, ctx: Context) -> Optional[Finding]:
    url = finding.target
    if not url.startswith("https://"):
        url = f"https://{url.split('://', 1)[-1]}"
    r = _get(url)
    if not r:
        return None
    hsts = r.headers.get("Strict-Transport-Security", "")
    if not hsts:
        return _attach_proof(finding,
            method="hsts_header_check",
            request=f"GET {url}",
            response=f"HTTP {r.status_code}\nStrict-Transport-Security: (absent)",
        )
    return None


def unauth_endpoint(finding: Finding, ctx: Context) -> Optional[Finding]:
    r = _get(finding.target)
    if not r:
        return None
    if r.status_code == 200 and len(r.content) > 100:
        return _attach_proof(finding,
            method="unauthenticated_access",
            request=f"GET {finding.target}\n(no Authorization header)",
            response=f"HTTP {r.status_code}, {len(r.content)} bytes",
        )
    return None


def options_method(finding: Finding, ctx: Context) -> Optional[Finding]:
    try:
        r = requests.options(finding.target, timeout=API_TIMEOUT)
    except Exception:
        return None
    allow = r.headers.get("Allow", r.headers.get("Access-Control-Allow-Methods", ""))
    dangerous = [m for m in ("PUT", "DELETE", "TRACE", "CONNECT", "PATCH")
                 if m in allow.upper()]
    if dangerous:
        return _attach_proof(finding,
            method="options_method_check",
            request=f"OPTIONS {finding.target}",
            response=f"HTTP {r.status_code}\nAllow: {allow}\nDangerous: {dangerous}",
        )
    return None


def git_exposure(finding: Finding, ctx: Context) -> Optional[Finding]:
    base = finding.target.rstrip("/").rstrip("HEAD")
    head_url = base.rstrip("/") + "/.git/HEAD" if ".git" not in base else base
    r = _get(head_url)
    if not r:
        return None
    if r.status_code == 200 and re.search(r"ref:\s*refs/heads/", r.text):
        return _attach_proof(finding,
            method="git_head_check",
            request=f"GET {head_url}",
            response=f"HTTP 200\n{r.text[:200]}",
        )
    return None


# ─────────────────────────────────────────────────────────────────────────────
# Dispatcher — maps category/title keywords to verifier functions
# ─────────────────────────────────────────────────────────────────────────────

_TITLE_VERIFIERS: list[tuple[list[str], VerifierFn]] = [
    (["clickjacking"],                        lambda f, c: None),  # handled by verify/clickjacking.py
    (["cors", "wildcard"],                    cors_wildcard),
    (["open redirect"],                       open_redirect),
    (["directory listing", "directory index"],directory_listing),
    (["git repository", "git exposed"],       git_exposure),
    (["sensitive file", "environment file",
      "backup", "database dump", "config file",
      "phpMyAdmin", "server-status"],         sensitive_file),
    (["debug", "error information", "stack"], error_disclosure),
    (["hsts", "strict transport"],            hsts_missing),
    (["http", "not redirected"],              http_no_redirect),
    (["unauthenticated", "without authentication",
      "api endpoint returns"],                unauth_endpoint),
    (["dangerous http method", "options"],    options_method),
]


def run_verifier(finding: Finding, ctx: Context) -> Optional[Finding]:
    """
    Select and run the appropriate verifier for a finding.
    Returns the finding with proof attached, or None if no verifier matched
    or verification failed.
    """
    title_lower = finding.title.lower()
    for keywords, fn in _TITLE_VERIFIERS:
        if any(kw in title_lower for kw in keywords):
            try:
                return fn(finding, ctx)
            except Exception as e:
                logger.debug(f"Verifier failed for '{finding.title}': {e}")
                return None
    return None


def verify_all(findings: list[Finding], ctx: Context) -> tuple[int, int]:
    """
    Run confirmation engine over all findings.
    Returns (verified_count, attempted_count).
    """
    attempted = verified = 0
    for f in findings:
        result = run_verifier(f, ctx)
        if result is not None:
            attempted += 1
            f.proof = result.proof
            if f.proof.verified:
                verified += 1
                logger.info(f"✓ Verified: {f.title} @ {f.target}")
    return verified, attempted
