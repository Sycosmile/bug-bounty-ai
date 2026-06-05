"""Safe subprocess wrapper for security tools"""

import subprocess
import logging
from typing import List
from config import TOOL_TIMEOUT

logger = logging.getLogger(__name__)


def run_cmd(cmd: List[str]) -> List[str]:
    """Execute external command safely
    
    Args:
        cmd: Command and arguments as list
    
    Returns:
        List of output lines
    """
    logger.debug(f"Executing command: {' '.join(cmd)}")
    
    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=TOOL_TIMEOUT,
            check=False,  # Don't raise on non-zero exit
        )
        
        if result.returncode != 0 and result.stderr:
            logger.warning(
                f"Command '{cmd[0]}' exited with code {result.returncode}: "
                f"{result.stderr[:200]}"
            )
        
        # Return stdout lines, filtering empty ones
        output = [line.strip() for line in result.stdout.splitlines() if line.strip()]
        logger.debug(f"Command returned {len(output)} lines")
        return output
    
    except subprocess.TimeoutExpired:
        error_msg = f"Command timed out after {TOOL_TIMEOUT}s: {cmd[0]}"
        logger.warning(error_msg)
        return [f"[TIMEOUT] {error_msg}"]
    
    except FileNotFoundError:
        error_msg = f"Command not found: {cmd[0]} (install the tool or add to PATH)"
        logger.warning(error_msg)
        return [f"[NOT FOUND] {error_msg}"]
    
    except Exception as e:
        error_msg = f"Command execution failed: {str(e)}"
        logger.error(error_msg)
        return [f"[ERROR] {error_msg}"]
