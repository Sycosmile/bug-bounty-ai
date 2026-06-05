"""Mock nikto for demo (returns realistic vulnerability data)"""

import logging
from tools.executor import run_cmd

logger = logging.getLogger(__name__)


def run_nikto(target: str) -> list:
    """Run nikto or use mock data if not available
    
    Args:
        target: Target domain
    
    Returns:
        List of vulnerabilities found
    """
    # Try real nikto first
    try:
        result = run_cmd(["nikto", "-h", target])
        if result and not any("[" in line for line in result):
            return result
    except Exception:
        pass
    
    # Fall back to mock data for demo
    logger.info(f"Using mock web scan data for {target}")
    mock_findings = [
        "[WEB_SCAN] Server banner discloses Apache version",
        "[WEB_SCAN] X-Frame-Options header missing",
        "[WEB_SCAN] X-Content-Type-Options header missing",
        "[WEB_SCAN] Outdated jQuery library detected (1.7.2)",
        "[WEB_SCAN] HTTP methods: GET, POST, PUT, DELETE exposed",
    ]
    return mock_findings
