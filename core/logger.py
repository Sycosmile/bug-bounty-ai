"""Phase 2: Enhanced logging with Loguru (fallback to stdlib)"""

import sys
import logging
from pathlib import Path
from typing import Optional

try:
    from loguru import logger as loguru_logger
    LOGURU_AVAILABLE = True
except ImportError:
    LOGURU_AVAILABLE = False

from config import LOG_LEVEL, LOG_FORMAT, settings


class LoggerManager:
    """Manages logging with Loguru or stdlib fallback"""
    
    def __init__(self, name: str = "bug-bounty-ai"):
        self.name = name
        self.use_loguru = LOGURU_AVAILABLE
        
        if self.use_loguru:
            self._setup_loguru()
        else:
            self._setup_stdlib()
    
    def _setup_loguru(self):
        """Setup Loguru logger"""
        # Remove default handler
        loguru_logger.remove()
        
        # Console output
        loguru_logger.add(
            sys.stdout,
            format="<green>{time:YYYY-MM-DD HH:mm:ss}</green> | <level>{level: <8}</level> | <cyan>{name}</cyan>:<cyan>{function}</cyan> - <level>{message}</level>",
            level=LOG_LEVEL,
            colorize=True,
        )
        
        # File output
        log_file = settings.log_file
        loguru_logger.add(
            log_file,
            format="{time:YYYY-MM-DD HH:mm:ss} | {level: <8} | {name}:{function} - {message}",
            level="DEBUG",
            rotation="500 MB",
            retention="7 days",
            compression="zip",
        )
        
        self.logger = loguru_logger
    
    def _setup_stdlib(self):
        """Setup stdlib logger with fallback"""
        self.logger = logging.getLogger(self.name)
        self.logger.setLevel(LOG_LEVEL)
        
        # Console handler
        console_handler = logging.StreamHandler(sys.stdout)
        console_handler.setFormatter(logging.Formatter(LOG_FORMAT))
        self.logger.addHandler(console_handler)
        
        # File handler
        log_file = Path(settings.log_file)
        file_handler = logging.FileHandler(log_file)
        file_handler.setFormatter(logging.Formatter(LOG_FORMAT))
        self.logger.addHandler(file_handler)
    
    def __getattr__(self, name):
        """Delegate logger methods"""
        return getattr(self.logger, name)


def get_logger(name: str) -> LoggerManager:
    """Get or create a logger
    
    Args:
        name: Logger name (usually __name__)
    
    Returns:
        LoggerManager instance
    """
    return LoggerManager(name)
