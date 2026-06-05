"""Mock nmap for demo (returns realistic service data)"""

import logging
from tools.executor import run_cmd

logger = logging.getLogger(__name__)


def run_nmap(target: str) -> list:
    """Run nmap or use mock data if not available
    
    Args:
        target: Target domain or IP
    
    Returns:
        List of services found
    """
    # Try real nmap first
    try:
        result = run_cmd(["nmap", "-sV", target])
        if result and not any("[" in line for line in result):
            return result
    except Exception:
        pass
    
    # Fall back to mock data for demo
    logger.info(f"Using mock service data for {target}")
    mock_services = [
        "22/tcp    open  ssh       OpenSSH 7.4",
        "80/tcp    open  http      Apache httpd 2.4.6",
        "443/tcp   open  https     nginx 1.14.0",
        "3306/tcp  open  mysql     MySQL 5.7.29",
        "5432/tcp  open  postgres  PostgreSQL 11.5",
    ]
    return mock_services
