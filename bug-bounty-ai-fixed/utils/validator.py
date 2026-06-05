import re
import ipaddress
from urllib.parse import urlparse
from config import ALLOW_IP_TARGETS, ALLOW_PRIVATE_NETWORKS


def validate_target(target: str) -> bool:
    """
    Validate scan target for safe autonomous execution.
    Only allows valid HTTP/HTTPS domains (or IPs if enabled).
    """

    if not target or not isinstance(target, str):
        return False

    # Normalize: if no scheme, assume https
    if "://" not in target:
        target = "https://" + target

    parsed = urlparse(target)

    # -------------------------
    # SCHEME CHECK
    # -------------------------
    if parsed.scheme not in ["http", "https"]:
        return False

    host = parsed.hostname

    if not host:
        return False

    # -------------------------
    # BLOCK LOCAL / UNSAFE HOSTS (always, regardless of flags)
    # -------------------------
    blocked_hosts = {"localhost", "127.0.0.1", "0.0.0.0", "::1"}

    if host in blocked_hosts:
        return False

    # -------------------------
    # IP VALIDATION
    # -------------------------
    try:
        ip = ipaddress.ip_address(host)
        is_ip = True
    except ValueError:
        is_ip = False

    if is_ip:
        if not ALLOW_IP_TARGETS:
            return False

        # Block loopback/link-local/unspecified always
        if ip.is_loopback or ip.is_unspecified or ip.is_link_local:
            return False

        # Block private ranges unless explicitly allowed
        if ip.is_private and not ALLOW_PRIVATE_NETWORKS:
            return False

    # -------------------------
    # DOMAIN VALIDATION
    # -------------------------
    if not is_ip:
        # must look like a real domain
        domain_regex = r"^(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}$"
        if not re.match(domain_regex, host):
            return False

    return True
