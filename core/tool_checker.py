"""Tool availability checker"""

import shutil

REQUIRED_TOOLS = [
    "subfinder",
    "nmap",
    "nikto",
]

def check_tools():
    """Return availability status for required tools"""
    return {
        tool: shutil.which(tool) is not None
        for tool in REQUIRED_TOOLS
    }
