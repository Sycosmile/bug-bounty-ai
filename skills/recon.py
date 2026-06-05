"""Recon skill — subdomain + host discovery."""

from __future__ import annotations

import logging
import re
import socket

import requests

from config import API_TIMEOUT
from core.context import Context
from core.models import Finding, Severity, FindingCategory
from tools.executor import run_cmd

logger = logging.getLogger(__name__)

COMMON_SUBS = [
    "www", "mail", "api", "dev", "staging", "test", "admin",
    "blog", "shop", "app", "portal", "vpn", "cdn", "static",
    "auth", "login", "dashboard", "beta", "old", "backup",
]


def _bare_domain(target: str) -> str:
    target = re.sub(r"^https?://", "", target)
    return target.split("/")[0].split(":")[0]


def _resolve(host: str) -> str | None:
    try:
        return socket.gethostbyname(host)
    except socket.gaierror:
        return None


def _http_live_check(host: str, context: Context) -> None:
    for scheme in ("https", "http"):
        url = f"{scheme}://{host}"
        try:
            r = requests.get(url, timeout=API_TIMEOUT, allow_redirects=True)
            svc = f"{url} [HTTP {r.status_code}]"
            if svc not in context.services:
                context.services.append(svc)
            logger.info(f"Live: {url} → {r.status_code}")
            return
        except Exception:
            continue


def _fallback_recon(domain: str, context: Context) -> None:
    logger.info("subfinder unavailable — DNS/HTTP fallback recon")

    ip = _resolve(domain)
    if ip:
        if domain not in context.subdomains:
            context.subdomains.append(domain)
        context.insights.append({"type": "recon", "message": f"{domain} → {ip}"})
        logger.info(f"Resolved {domain} → {ip}")
    else:
        logger.warning(f"Could not resolve {domain}")

    for sub in COMMON_SUBS:
        host = f"{sub}.{domain}"
        if _resolve(host):
            if host not in context.subdomains:
                context.subdomains.append(host)
                logger.info(f"Subdomain found: {host}")

    _http_live_check(domain, context)

    if len(context.subdomains) > 1:
        context.add_finding(Finding(
            title=f"Subdomain enumeration: {len(context.subdomains)} hosts discovered",
            severity=Severity.INFO,
            category=FindingCategory.RECON,
            source="recon",
            target=domain,
            description=f"Discovered hosts: {', '.join(context.subdomains[:10])}",
            confidence=0.9,
        ))


def run(context: Context) -> Context:
    logger.info(f"Starting recon on {context.target}")
    domain = _bare_domain(context.target)

    if context.tool_status.get("subfinder"):
        try:
            subs = run_cmd(["subfinder", "-d", domain, "-silent"])
            for s in subs:
                if s not in context.subdomains:
                    context.subdomains.append(s)
            logger.info(f"subfinder: {len(subs)} subdomains")
            _http_live_check(domain, context)
        except Exception as e:
            logger.error(f"subfinder failed: {e}")
            context.add_error("recon", str(e))
            _fallback_recon(domain, context)
    else:
        _fallback_recon(domain, context)

    if not context.subdomains:
        context.subdomains.append(domain)

    return context


skill = {"name": "recon", "run": run}
