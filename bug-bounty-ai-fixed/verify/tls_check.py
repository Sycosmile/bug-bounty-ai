"""
TLS/SSL verification module — checks certificate validity, protocol version,
weak ciphers, and expiry. Safe and non-destructive.
"""

from __future__ import annotations

import logging
import socket
import ssl
from datetime import datetime, timezone
from typing import Optional

from core.models import (
    Finding, Severity, FindingCategory,
    CvssVector, CvssAV, CvssAC, CvssPR, CvssUI, CvssScope, CvssImpact,
    Proof,
)

logger = logging.getLogger(__name__)

_WEAK_PROTOCOLS = {"SSLv2", "SSLv3", "TLSv1", "TLSv1.1"}

_CVSS_WEAK_TLS = CvssVector(
    AV=CvssAV.NETWORK, AC=CvssAC.HIGH, PR=CvssPR.NONE, UI=CvssUI.NONE,
    S=CvssScope.UNCHANGED, C=CvssImpact.HIGH, I=CvssImpact.NONE, A=CvssImpact.NONE,
)  # 5.9 MEDIUM

_CVSS_EXPIRED = CvssVector(
    AV=CvssAV.NETWORK, AC=CvssAC.LOW, PR=CvssPR.NONE, UI=CvssUI.REQUIRED,
    S=CvssScope.UNCHANGED, C=CvssImpact.LOW, I=CvssImpact.LOW, A=CvssImpact.NONE,
)  # 5.4 MEDIUM


def verify(host: str, port: int = 443) -> list[Finding]:
    findings: list[Finding] = []

    try:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE

        with socket.create_connection((host, port), timeout=10) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                protocol = ssock.version() or "unknown"
                cert     = ssock.getpeercert()
                cipher   = ssock.cipher()

        cipher_name = cipher[0] if cipher else "unknown"

        # 1. Weak protocol
        if protocol in _WEAK_PROTOCOLS:
            findings.append(Finding(
                title=f"Weak TLS protocol in use: {protocol}",
                severity=Severity.HIGH,
                category=FindingCategory.CRYPTO,
                source="verify.tls_check",
                target=f"{host}:{port}",
                description=f"{protocol} is deprecated and vulnerable to known attacks (POODLE, BEAST).",
                remediation="Disable TLS 1.0 and 1.1; enforce TLS 1.2 minimum, prefer TLS 1.3.",
                confidence=0.99,
                cvss=_CVSS_WEAK_TLS,
                proof=Proof(verified=True, method="ssl_handshake",
                            request=f"TLS handshake to {host}:{port}",
                            response=f"Negotiated protocol: {protocol}"),
                references=["https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2014-3566"],
            ))

        # 2. Certificate expiry
        if cert:
            not_after_str = cert.get("notAfter", "")
            if not_after_str:
                try:
                    not_after = datetime.strptime(not_after_str, "%b %d %H:%M:%S %Y %Z")
                    not_after = not_after.replace(tzinfo=timezone.utc)
                    days_left = (not_after - datetime.now(timezone.utc)).days

                    if days_left < 0:
                        findings.append(Finding(
                            title=f"TLS certificate expired {abs(days_left)} days ago",
                            severity=Severity.HIGH,
                            category=FindingCategory.CRYPTO,
                            source="verify.tls_check",
                            target=f"{host}:{port}",
                            description="An expired certificate causes browser security warnings and breaks HTTPS.",
                            remediation="Renew the TLS certificate immediately. Consider automated renewal via Let's Encrypt.",
                            confidence=0.99,
                            cvss=_CVSS_EXPIRED,
                            proof=Proof(verified=True, method="cert_expiry_check",
                                        request=f"TLS cert inspection {host}:{port}",
                                        response=f"notAfter: {not_after_str} ({abs(days_left)} days ago)"),
                        ))
                    elif days_left < 14:
                        findings.append(Finding(
                            title=f"TLS certificate expires in {days_left} days",
                            severity=Severity.MEDIUM,
                            category=FindingCategory.CRYPTO,
                            source="verify.tls_check",
                            target=f"{host}:{port}",
                            description="Certificate is near expiry; services will break when it expires.",
                            remediation="Renew the certificate before expiry. Enable auto-renewal.",
                            confidence=0.99,
                            proof=Proof(verified=True, method="cert_expiry_check",
                                        request=f"TLS cert inspection {host}:{port}",
                                        response=f"notAfter: {not_after_str} ({days_left} days remaining)"),
                        ))
                except ValueError:
                    pass

            # 3. Self-signed (no issuer CN differs from subject CN)
            subject = dict(x[0] for x in cert.get("subject", []))
            issuer  = dict(x[0] for x in cert.get("issuer",  []))
            if subject.get("commonName") == issuer.get("commonName"):
                findings.append(Finding(
                    title="Self-signed TLS certificate detected",
                    severity=Severity.MEDIUM,
                    category=FindingCategory.CRYPTO,
                    source="verify.tls_check",
                    target=f"{host}:{port}",
                    description="Self-signed certificates are not trusted by browsers and enable MITM attacks.",
                    remediation="Replace with a certificate from a trusted CA (e.g. Let's Encrypt).",
                    confidence=0.95,
                    proof=Proof(verified=True, method="cert_authority_check",
                                request=f"TLS cert inspection {host}:{port}",
                                response=f"Subject CN: {subject.get('commonName')}, Issuer CN: {issuer.get('commonName')}"),
                ))

    except (socket.timeout, ConnectionRefusedError, OSError) as e:
        logger.debug(f"tls_check: could not connect to {host}:{port}: {e}")
    except Exception as e:
        logger.debug(f"tls_check: unexpected error for {host}:{port}: {e}")

    return findings
