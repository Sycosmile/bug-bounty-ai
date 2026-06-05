"""Exposure skill — port/service discovery."""

from __future__ import annotations

import logging
import socket

from core.context import Context
from core.models import Finding, Severity, FindingCategory
from tools.executor import run_cmd

logger = logging.getLogger(__name__)

# port → (label, severity, description, remediation)
PORT_REGISTRY: dict[int, tuple[str, Severity, str, str]] = {
    21:    ("FTP service exposed",       Severity.HIGH,     "FTP transmits credentials in plaintext.",                          "Disable FTP; use SFTP/SCP instead."),
    22:    ("SSH service exposed",       Severity.LOW,      "SSH is exposed. Acceptable if hardened.",                         "Restrict to known IPs; disable password auth."),
    23:    ("Telnet service exposed",    Severity.CRITICAL, "Telnet transmits all data including credentials in plaintext.",    "Disable immediately; replace with SSH."),
    25:    ("SMTP service exposed",      Severity.MEDIUM,   "Open SMTP may allow relay abuse.",                                "Restrict relay; require authentication."),
    53:    ("DNS service exposed",       Severity.LOW,      "DNS is publicly reachable.",                                      "Disable recursion; restrict zone transfers."),
    80:    ("Unencrypted HTTP",          Severity.LOW,      "HTTP traffic is unencrypted.",                                    "Redirect all HTTP to HTTPS."),
    443:   ("HTTPS service",            Severity.INFO,     "HTTPS is available.",                                             "Ensure TLS 1.2+ and valid certificate."),
    3306:  ("MySQL exposed",            Severity.CRITICAL, "Database port directly accessible from the internet.",            "Bind to localhost; use VPN for remote access."),
    5432:  ("PostgreSQL exposed",       Severity.CRITICAL, "Database port directly accessible from the internet.",            "Bind to localhost; use VPN for remote access."),
    6379:  ("Redis exposed",            Severity.CRITICAL, "Redis has no auth by default; full read/write access possible.",  "Bind to localhost; enable requirepass."),
    8080:  ("HTTP alt-port exposed",    Severity.MEDIUM,   "HTTP on non-standard port may be a dev/admin interface.",         "Restrict access or move behind reverse proxy."),
    8443:  ("HTTPS alt-port exposed",   Severity.LOW,      "HTTPS on non-standard port.",                                     "Verify this is intentional."),
    27017: ("MongoDB exposed",          Severity.CRITICAL, "MongoDB may have no auth; full DB access possible.",              "Enable authentication; bind to localhost."),
}

SCAN_PORTS = list(PORT_REGISTRY.keys())


def _socket_scan(host: str, context: Context) -> None:
    logger.info(f"Socket port scan on {host}")
    for port in SCAN_PORTS:
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(1.5)
            if s.connect_ex((host, port)) == 0:
                label, severity, description, remediation = PORT_REGISTRY[port]
                svc = f"{host}:{port} ({label})"
                if svc not in context.services:
                    context.services.append(svc)
                if severity != Severity.INFO:
                    context.add_finding(Finding(
                        title=label,
                        severity=severity,
                        category=FindingCategory.EXPOSURE,
                        source="socket_scan",
                        target=f"{host}:{port}",
                        description=description,
                        remediation=remediation,
                        confidence=0.85,
                    ))
                    logger.info(f"Open port: {host}:{port} — {label}")
            s.close()
        except Exception:
            pass


def run(context: Context) -> Context:
    logger.info(f"Starting exposure scan on {context.target}")
    hosts = list(dict.fromkeys(context.subdomains)) or [context.target]

    for host in hosts[:5]:
        if context.tool_status.get("nmap"):
            try:
                lines = run_cmd(["nmap", "-sV", "--open", "-T4",
                                 "-p", ",".join(str(p) for p in SCAN_PORTS), host])
                for line in lines:
                    ll = line.lower()
                    for port, (label, severity, desc, rem) in PORT_REGISTRY.items():
                        if str(port) in line and ("open" in ll or "tcp" in ll):
                            svc = f"{host}:{port} ({label})"
                            if svc not in context.services:
                                context.services.append(svc)
                            if severity != Severity.INFO:
                                context.add_finding(Finding(
                                    title=label,
                                    severity=severity,
                                    category=FindingCategory.EXPOSURE,
                                    source="nmap",
                                    target=f"{host}:{port}",
                                    description=desc,
                                    remediation=rem,
                                    confidence=0.9,
                                ))
            except Exception as e:
                logger.error(f"nmap failed: {e}")
                context.add_error("exposure", str(e))
                _socket_scan(host, context)
        else:
            _socket_scan(host, context)

    return context


skill = {"name": "exposure", "run": run}
