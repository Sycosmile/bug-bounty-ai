"""Mock subfinder for demo (returns realistic subdomain data)"""

import logging
from tools.executor import run_cmd

logger = logging.getLogger(__name__)


def run_subfinder(domain: str) -> list:
    """Run subfinder or use mock data if not available
    
    Args:
        domain: Target domain
    
    Returns:
        List of subdomains
    """
    # Try real subfinder first
    try:
        result = run_cmd(["subfinder", "-d", domain, "-silent"])
        if result and not any("[" in line for line in result):
            return result
    except Exception:
        pass
    
    # Fall back to mock data for demo
    logger.info(f"Using mock subdomain data for {domain}")
    mock_subdomains = [
        f"www.{domain}",
        f"api.{domain}",
        f"admin.{domain}",
        f"dev.{domain}",
        f"staging.{domain}",
        f"mail.{domain}",
        f"cdn.{domain}",
    ]
    return mock_subdomains
