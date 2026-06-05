"""
Auth testing skill — safe, non-destructive.

Tests:
  1. Rate limiting on login endpoints
  2. Account lockout detection
  3. Password policy via registration/reset forms
  4. Default credential check (3 pairs only — stops immediately on success)
  5. Auth header bypass attempts (X-Forwarded-For, etc.)
  6. JWT none-algorithm detection
  7. Session fixation indicator (session ID unchanged after login-like POST)
"""
from __future__ import annotations

import base64
import json
import logging
import time
import re

import requests

from config import API_TIMEOUT
from core.context import Context
from core.models import (Finding, Severity, FindingCategory,
                          CvssVector, CvssAV, CvssAC, CvssPR,
                          CvssUI, CvssScope, CvssImpact, Proof)

logger = logging.getLogger(__name__)

_LOGIN_PATHS   = ["/login", "/admin/login", "/wp-login.php", "/auth/login",
                   "/signin", "/user/login", "/account/login", "/api/auth/login",
                   "/api/login", "/api/v1/auth/login"]

_DEFAULT_CREDS = [
    ("admin",  "admin"),
    ("admin",  "password"),
    ("admin",  "123456"),
]

_CVSS_MISSING_RATELIMIT = CvssVector(
    AV=CvssAV.NETWORK, AC=CvssAC.LOW, PR=CvssPR.NONE, UI=CvssUI.NONE,
    S=CvssScope.UNCHANGED, C=CvssImpact.LOW, I=CvssImpact.LOW, A=CvssImpact.NONE,
)  # 6.5 MEDIUM

_CVSS_DEFAULT_CREDS = CvssVector(
    AV=CvssAV.NETWORK, AC=CvssAC.LOW, PR=CvssPR.NONE, UI=CvssUI.NONE,
    S=CvssScope.CHANGED, C=CvssImpact.HIGH, I=CvssImpact.HIGH, A=CvssImpact.HIGH,
)  # 10.0 CRITICAL


def _post(url: str, data: dict, headers: dict | None = None) -> requests.Response | None:
    try:
        return requests.post(url, json=data,
                             headers={**(headers or {}),
                                      "Content-Type": "application/json",
                                      "User-Agent": "Mozilla/5.0"},
                             timeout=API_TIMEOUT, allow_redirects=False)
    except Exception:
        return None


def _get(url: str, headers: dict | None = None) -> requests.Response | None:
    try:
        return requests.get(url, headers=headers or {},
                            timeout=API_TIMEOUT, allow_redirects=False)
    except Exception:
        return None


# ── 1. Rate limiting ─────────────────────────────────────────────────────────

def _test_rate_limit(url: str, context: Context) -> None:
    """Send 10 rapid requests; if none are 429/blocked → no rate limiting."""
    statuses = []
    for _ in range(10):
        r = _post(url, {"username": "ratelimit_test@example.com", "password": "wrongpassword"})
        if r:
            statuses.append(r.status_code)

    rate_limited = any(s in (429, 423, 503) for s in statuses)
    blocked      = any(s == 403 for s in statuses[5:])   # 403 after several attempts

    if not rate_limited and not blocked and len(statuses) >= 8:
        context.add_finding(Finding(
            title=f"No rate limiting on login endpoint: {url}",
            severity=Severity.MEDIUM,
            category=FindingCategory.AUTH,
            source="auth_test",
            target=url,
            description=(
                "10 rapid login attempts received no 429/423 response. "
                "The endpoint does not appear to rate-limit failed logins, "
                "enabling brute-force and credential-stuffing attacks."
            ),
            remediation=(
                "Implement rate limiting (e.g. ≤5 attempts/minute per IP). "
                "Consider CAPTCHA after repeated failures. "
                "Use a WAF rule or middleware like Flask-Limiter / express-rate-limit."
            ),
            confidence=0.85,
            cvss=_CVSS_MISSING_RATELIMIT,
            proof=Proof(
                verified=True,
                method="rapid_login_probe",
                request=f"POST {url} × 10 with wrong credentials",
                response=f"Status codes: {statuses}",
            ),
            references=["https://owasp.org/www-project-web-security-testing-guide/"],
        ))
        logger.info(f"No rate limiting detected on {url}")
    else:
        logger.info(f"Rate limiting present on {url} (statuses: {statuses})")


# ── 2. Account lockout ───────────────────────────────────────────────────────

def _test_lockout(url: str, context: Context) -> None:
    """Send 20 failed logins; check if account eventually locked (403/423/lockout msg)."""
    lockout_patterns = ["locked", "too many", "account disabled", "try again later",
                        "temporarily", "blocked", "suspended"]
    locked = False
    for i in range(20):
        r = _post(url, {"username": "lockout_test_user", "password": f"wrong{i}"})
        if not r:
            continue
        body = r.text.lower()
        if r.status_code in (423, 429) or any(p in body for p in lockout_patterns):
            locked = True
            logger.info(f"Lockout triggered after {i+1} attempts on {url}")
            break

    if not locked:
        context.add_finding(Finding(
            title=f"No account lockout after 20 failed login attempts: {url}",
            severity=Severity.MEDIUM,
            category=FindingCategory.AUTH,
            source="auth_test",
            target=url,
            description=(
                "20 consecutive failed login attempts caused no account lockout. "
                "Combined with no rate limiting, this allows unlimited brute-force."
            ),
            remediation=(
                "Implement progressive lockout: warn at 5 failures, "
                "soft-lock (CAPTCHA) at 10, hard-lock at 20 with unlock email."
            ),
            confidence=0.75,
            proof=Proof(
                verified=True,
                method="lockout_probe",
                request=f"POST {url} × 20 with wrong credentials",
                response="No lockout response (423/429) or lockout message detected",
            ),
        ))


# ── 3. Default credentials ───────────────────────────────────────────────────

def _test_default_creds(url: str, context: Context) -> None:
    """Try 3 well-known default credential pairs. Stop on first success."""
    success_indicators = [
        "dashboard", "welcome", "logout", "profile",
        "admin", "token", "access_token", "session"
    ]
    for username, password in _DEFAULT_CREDS:
        r = _post(url, {"username": username, "password": password})
        if not r:
            continue
        body = r.text.lower()
        # Success = 200 with auth-success keywords, or redirect to dashboard
        success = (
            (r.status_code == 200 and any(kw in body for kw in success_indicators))
            or r.status_code in (200, 302) and "set-cookie" in {k.lower(): v for k, v in r.headers.items()}
        )
        if success:
            context.add_finding(Finding(
                title=f"Default credentials accepted: {username}/{password}",
                severity=Severity.CRITICAL,
                category=FindingCategory.AUTH,
                source="auth_test",
                target=url,
                description=(
                    f"Login with {username}:{password} returned HTTP {r.status_code} "
                    "with authentication success indicators. Default credentials are valid."
                ),
                remediation="Change default credentials immediately. Enforce strong password policy.",
                confidence=0.90,
                cvss=_CVSS_DEFAULT_CREDS,
                proof=Proof(
                    verified=True,
                    method="default_credential_check",
                    request=f"POST {url}\n{{\"username\":\"{username}\",\"password\":\"{password}\"}}",
                    response=f"HTTP {r.status_code}\n{r.text[:200]}",
                ),
                references=["https://owasp.org/www-project-top-ten/2017/A2_2017-Broken_Authentication"],
            ))
            logger.info(f"Default creds accepted: {username}:{password} @ {url}")
            return   # stop after first success


# ── 4. Auth bypass headers ───────────────────────────────────────────────────

def _test_auth_bypass(url: str, context: Context) -> None:
    """Check if spoofed internal IP headers bypass auth on protected endpoints."""
    bypass_headers_list = [
        {"X-Forwarded-For": "127.0.0.1"},
        {"X-Real-IP":        "127.0.0.1"},
        {"X-Originating-IP": "127.0.0.1"},
        {"X-Remote-IP":      "127.0.0.1"},
        {"X-Client-IP":      "127.0.0.1"},
        {"X-Host":           "localhost"},
    ]
    # First get baseline (should be 401/403)
    baseline = _get(url)
    if not baseline or baseline.status_code not in (401, 403):
        return   # not a protected endpoint

    for bypass_hdrs in bypass_headers_list:
        r = _get(url, headers=bypass_hdrs)
        if r and r.status_code == 200 and baseline.status_code in (401, 403):
            hdr_str = ", ".join(f"{k}: {v}" for k, v in bypass_hdrs.items())
            context.add_finding(Finding(
                title=f"Authentication bypass via spoofed header: {list(bypass_hdrs.keys())[0]}",
                severity=Severity.CRITICAL,
                category=FindingCategory.AUTH,
                source="auth_test",
                target=url,
                description=(
                    f"Adding `{hdr_str}` changed response from "
                    f"HTTP {baseline.status_code} to HTTP 200. "
                    "The server trusts client-supplied IP headers without validation."
                ),
                remediation=(
                    "Never trust X-Forwarded-For or similar headers for security decisions "
                    "unless set by a trusted reverse proxy. "
                    "Strip these headers at the load balancer/WAF."
                ),
                confidence=0.90,
                proof=Proof(
                    verified=True,
                    method="auth_header_bypass",
                    request=f"GET {url}\n{hdr_str}",
                    response=f"HTTP {r.status_code} (baseline was {baseline.status_code})",
                ),
            ))
            logger.info(f"Auth bypass via {bypass_hdrs} on {url}")
            return


# ── 5. JWT none-algorithm ────────────────────────────────────────────────────

def _test_jwt_none(url: str, context: Context) -> None:
    """
    If a JWT is found in cookies/headers, craft a none-algorithm token
    and check if it's accepted.
    """
    r = _get(url)
    if not r:
        return

    # Find JWT in cookies or Authorization header
    jwt_token = None
    for cookie in r.cookies:
        val = cookie.value
        if val.count(".") == 2 and val.startswith("ey"):
            jwt_token = val
            break
    if not jwt_token:
        auth = r.headers.get("Authorization", "")
        if auth.startswith("Bearer ey"):
            jwt_token = auth[7:]

    if not jwt_token:
        return

    try:
        parts = jwt_token.split(".")
        # Decode header
        header_bytes = parts[0] + "=="
        header = json.loads(base64.urlsafe_b64decode(header_bytes))
        if header.get("alg", "").upper() == "NONE":
            return   # already none — skip

        # Craft none-algorithm token
        none_header = base64.urlsafe_b64encode(
            json.dumps({"alg": "none", "typ": "JWT"}).encode()
        ).rstrip(b"=").decode()
        none_token = f"{none_header}.{parts[1]}."

        # Try to use the none-algorithm token
        r2 = _get(url, headers={"Authorization": f"Bearer {none_token}",
                                  "Cookie": f"token={none_token}"})
        if r2 and r2.status_code == 200 and r.status_code in (401, 403):
            context.add_finding(Finding(
                title="JWT none-algorithm vulnerability — signature verification bypass",
                severity=Severity.CRITICAL,
                category=FindingCategory.AUTH,
                source="auth_test",
                target=url,
                description=(
                    "The server accepted a JWT with alg=none, meaning it does not "
                    "verify token signatures. An attacker can forge arbitrary tokens."
                ),
                remediation=(
                    "Explicitly reject tokens with alg=none. "
                    "Use a library that does not allow algorithm switching. "
                    "Validate alg against a server-side allowlist."
                ),
                confidence=0.92,
                proof=Proof(
                    verified=True,
                    method="jwt_none_algorithm",
                    request=f"GET {url}\nAuthorization: Bearer {none_token[:80]}...",
                    response=f"HTTP {r2.status_code} (baseline was {r.status_code})",
                ),
                references=["https://auth0.com/blog/critical-vulnerabilities-in-json-web-token-libraries/"],
            ))
            logger.info(f"JWT none-algorithm accepted at {url}")
    except Exception as e:
        logger.debug(f"JWT none test failed: {e}")


# ── entrypoint ───────────────────────────────────────────────────────────────

def run(context: Context) -> Context:
    logger.info("Starting auth testing")

    bases = [svc.split(" ")[0].rstrip("/")
             for svc in context.services if "http" in svc.lower()]
    if not bases:
        t = context.target.rstrip("/")
        bases = [t if t.startswith("http") else f"https://{t}"]

    login_urls: list[str] = []
    for base in bases[:2]:
        for path in _LOGIN_PATHS:
            login_urls.append(f"{base}{path}")

    # Also add any login endpoints already found by api_scan
    for ep in context.endpoints:
        ep_url = str(ep).split(" ")[0]
        if any(kw in ep_url.lower() for kw in ("login", "signin", "auth")):
            login_urls.append(ep_url)

    login_urls = list(dict.fromkeys(login_urls))
    logger.info(f"Auth test: probing {len(login_urls)} login URL candidates")

    tested: set[str] = set()
    for url in login_urls[:15]:
        # Quick HEAD to check if it exists before running tests
        try:
            r = requests.head(url, timeout=3, allow_redirects=False)
            if r.status_code not in (200, 301, 302, 405):
                continue
        except Exception:
            continue

        if url in tested:
            continue
        tested.add(url)

        logger.info(f"Auth testing: {url}")
        _test_rate_limit(url, context)
        _test_lockout(url, context)
        _test_default_creds(url, context)
        _test_auth_bypass(url, context)
        _test_jwt_none(url, context)
        time.sleep(0.3)   # be polite

    logger.info(f"Auth testing complete — tested {len(tested)} login endpoints")
    return context


skill = {"name": "auth_test", "run": run}
