"""
Tech fingerprint skill — identify CMS, frameworks, server software, and
check for known-vulnerable versions against a local CVE hint table.
"""
from __future__ import annotations
import logging
import re
import requests
from config import API_TIMEOUT
from core.context import Context
from core.models import (Finding, Severity, FindingCategory,
                          CvssVector, CvssAV, CvssAC, CvssPR,
                          CvssUI, CvssScope, CvssImpact, Proof)

logger = logging.getLogger(__name__)

# (regex_on_body_or_header, tech_name, version_regex_group)
_FINGERPRINTS = [
    (r"wp-content/",                    "WordPress",   r"wordpress[/ ](\d+\.\d+[\.\d]*)"),
    (r"wp-includes/",                   "WordPress",   None),
    (r'content="WordPress (\S+)"',      "WordPress",   r'WordPress (\d[\d.]+)'),
    (r"Joomla!",                        "Joomla",      r"Joomla[/ ](\d+\.\d+[\.\d]*)"),
    (r"sites/default/files",            "Drupal",      r"Drupal (\d+\.\d+[\.\d]*)"),
    (r"laravel_session",                "Laravel",     None),
    (r"PHPSESSID",                      "PHP",         r"PHP/(\d+\.\d+[\.\d]*)"),
    (r"X-Powered-By: PHP/(\S+)",        "PHP",         r"PHP/(\S+)"),
    (r"Server: Apache/(\S+)",           "Apache",      r"Apache/(\S+)"),
    (r"Server: nginx/(\S+)",            "nginx",       r"nginx/(\S+)"),
    (r"Server: LiteSpeed",              "LiteSpeed",   None),
    (r"X-Generator: Drupal",            "Drupal",      None),
    (r"next\.js",                       "Next.js",     None),
    (r"__next",                         "Next.js",     None),
    (r"react",                          "React",       None),
    (r"struts",                         "Apache Struts",None),
]

# tech → [(min_ver, max_ver, cve, severity, title)]
# Simplified table — expand as needed
_VULN_DB: dict[str, list[tuple]] = {
    "WordPress": [
        ("0",   "6.3",  "CVE-2023-2745",  Severity.MEDIUM, "WordPress < 6.3 path traversal"),
        ("0",   "5.8",  "CVE-2021-39200", Severity.MEDIUM, "WordPress < 5.8 XSS via post slugs"),
    ],
    "PHP": [
        ("8.0", "8.0.28","CVE-2023-0662", Severity.HIGH,   "PHP 8.0.x < 8.0.28 DoS in parse_url"),
        ("8.1", "8.1.16","CVE-2023-0662", Severity.HIGH,   "PHP 8.1.x < 8.1.16 DoS in parse_url"),
        ("7.0", "7.99",  "CVE-2019-11043",Severity.CRITICAL,"PHP-FPM RCE (Nginx env_path_info)"),
    ],
    "Apache": [
        ("2.4", "2.4.49","CVE-2021-41773",Severity.CRITICAL,"Apache 2.4.49 path traversal / RCE"),
        ("2.4", "2.4.50","CVE-2021-42013",Severity.CRITICAL,"Apache 2.4.50 path traversal / RCE"),
    ],
    "Apache Struts": [
        ("0",   "2.5.30","CVE-2023-50164",Severity.CRITICAL,"Struts file upload path traversal RCE"),
    ],
}


def _ver_tuple(v: str) -> tuple:
    try:
        return tuple(int(x) for x in re.split(r"[.\-]", v)[:3])
    except Exception:
        return (0,)


def _check_vuln(tech: str, version_str: str | None, target: str) -> list[Finding]:
    vulns = []
    if tech not in _VULN_DB or not version_str:
        return vulns
    ver = _ver_tuple(version_str)
    for min_v, max_v, cve, severity, title in _VULN_DB[tech]:
        if _ver_tuple(min_v) <= ver <= _ver_tuple(max_v):
            vulns.append(Finding(
                title=f"Potentially vulnerable {tech} version: {title}",
                severity=severity,
                category=FindingCategory.MISCONFIGURED,
                source="tech_fingerprint",
                target=target,
                description=(
                    f"Detected {tech} version {version_str}. "
                    f"{title} ({cve}) affects versions {min_v}–{max_v}."
                ),
                remediation=f"Update {tech} to the latest stable release.",
                confidence=0.7,
                cve=cve,
                proof=Proof(
                    verified=True,
                    method="version_fingerprint",
                    request=f"HTTP response headers/body from {target}",
                    response=f"Detected: {tech}/{version_str}",
                ),
                references=[f"https://nvd.nist.gov/vuln/detail/{cve}"],
            ))
    return vulns


def run(context: Context) -> Context:
    logger.info("Starting technology fingerprinting")
    target = context.target.rstrip("/")
    if not target.startswith("http"):
        target = f"https://{target}"

    try:
        r = requests.get(target, timeout=API_TIMEOUT, allow_redirects=True)
    except Exception as e:
        logger.warning(f"tech_fingerprint: request failed: {e}")
        return context

    # Combine headers + body for fingerprinting
    combined = str(r.headers) + "\n" + r.text[:20000]
    detected: dict[str, str | None] = {}   # tech → version or None

    for pattern, tech, ver_pattern in _FINGERPRINTS:
        if re.search(pattern, combined, re.I):
            version = None
            if ver_pattern:
                m = re.search(ver_pattern, combined, re.I)
                if m:
                    version = m.group(1)
            # Don't overwrite a version we already found with None
            if tech not in detected or (detected[tech] is None and version):
                detected[tech] = version

    for tech, version in detected.items():
        ver_str = f" {version}" if version else ""
        logger.info(f"Detected: {tech}{ver_str}")

        # Version disclosure finding
        context.add_finding(Finding(
            title=f"Technology identified: {tech}{ver_str}",
            severity=Severity.INFO,
            category=FindingCategory.INFO_LEAK,
            source="tech_fingerprint",
            target=target,
            description=f"Server is running {tech}{ver_str}, detectable from HTTP responses.",
            remediation=f"Suppress version information in {tech} configuration.",
            confidence=0.85,
            evidence=f"Pattern matched in response headers/body",
        ))

        # CVE check
        for vuln_finding in _check_vuln(tech, version, target):
            context.add_finding(vuln_finding)
            logger.info(f"Potential CVE match: {vuln_finding.cve} for {tech} {version}")

    context.insights.append({
        "type": "tech_stack",
        "detected": {t: v for t, v in detected.items()},
    })

    return context


skill = {"name": "tech_fingerprint", "run": run}
