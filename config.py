"""PRO Autonomous Bug Bounty Configuration"""

import os
from pathlib import Path
from typing import List, Dict, Optional
from enum import Enum

try:
    from pydantic import BaseSettings, Field
    PYDANTIC_AVAILABLE = True
except ImportError:
    PYDANTIC_AVAILABLE = False
    BaseSettings = object


# -----------------------------
# ENUMS
# -----------------------------
class LogLevel(str, Enum):
    DEBUG = "DEBUG"
    INFO = "INFO"
    WARNING = "WARNING"
    ERROR = "ERROR"


class ExecutionMode(str, Enum):
    AUTO = "auto"
    SEQUENTIAL = "sequential"
    PARALLEL = "parallel"


class Severity(str, Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class TargetMode(str, Enum):
    SAFE = "safe"          # strict validation
    NORMAL = "normal"      # balanced
    LAB = "lab"            # allows IPs + local targets


# -----------------------------
# SETTINGS
# -----------------------------
if PYDANTIC_AVAILABLE:

    class Settings(BaseSettings):

        # =========================
        # CORE PATHS
        # =========================
        base_dir: Path = Field(default=Path(__file__).parent)
        skills_dir: Path = Field(default=None)
        tools_dir: Path = Field(default=None)

        # =========================
        # EXECUTION ENGINE
        # =========================
        execution_mode: ExecutionMode = Field(default=ExecutionMode.AUTO)
        max_iterations: int = Field(default=80, ge=10, le=1000)

        tool_timeout: int = Field(default=30, ge=5, le=300)
        api_timeout: int = Field(default=5, ge=1, le=30)
        max_skill_execution_time: int = Field(default=60, ge=10, le=300)

        enable_async: bool = Field(default=True)
        max_concurrent_tools: int = Field(default=6)

        # =========================
        # PRO AUTONOMY CONTROLS
        # =========================
        target_mode: TargetMode = Field(default=TargetMode.NORMAL)

        allow_ip_targets: bool = Field(default=False)
        allow_private_networks: bool = Field(default=False)

        auto_stop_on_high_risk: bool = Field(default=True)
        auto_stop_threshold: float = Field(default=30.0)

        soft_stop_findings_limit: int = Field(default=25)

        # =========================
        # SCORING ENGINE (CORE)
        # =========================
        severity_weights: Dict[str, float] = Field(default_factory=lambda: {
            "low": 1.0,
            "medium": 3.0,
            "high": 7.0,
            "critical": 12.0
        })

        confidence_multiplier: float = Field(default=1.2)
        exploitability_weight: float = Field(default=1.5)

        tool_reliability: Dict[str, float] = Field(default_factory=lambda: {
            "subfinder": 0.75,
            "nmap": 0.85,
            "nikto": 0.65
        })

        # =========================
        # SKILL SYSTEM
        # =========================
        skill_deps: Dict[str, List[str]] = Field(default_factory=dict)

        api_test_endpoints: List[str] = Field(default_factory=list)

        # =========================
        # LLM PLANNER (FUTURE)
        # =========================
        llm_provider: str = Field(default="none")
        llm_model: Optional[str] = None
        llm_api_key: Optional[str] = None
        llm_temperature: float = Field(default=0.3)

        # =========================
        # OBSERVABILITY
        # =========================
        log_level: LogLevel = Field(default=LogLevel.INFO)
        enable_detailed_logs: bool = Field(default=False)

        def __init__(self, **data):
            if "base_dir" in data:
                base_dir = data["base_dir"]
                data.setdefault("skills_dir", base_dir / "skills")
                data.setdefault("tools_dir", base_dir / "tools")
            super().__init__(**data)

        class Config:
            env_file = ".env"
            case_sensitive = False


    settings = Settings(
        skill_deps={
            "recon": [],
            "exposure": ["recon"],
            "web_scan": ["exposure"],
            "api_scan": ["web_scan"],
            "api_tester":      ["api_scan"],
    "verify":          ["web_scan"],
    "tech_fingerprint":["recon"],
    "passive_recon":   ["recon"],
    "sqli_detect":     ["api_scan"],
    "auth_test":       ["api_scan"],
    "poc_generator":   ["verify"],
    "report_submit":   ["poc_generator"],
            "inspector": ["recon", "exposure", "web_scan", "api_scan"],
            "report": ["recon", "exposure", "web_scan", "inspector"],
        },
        api_test_endpoints=[
            "/api",
            "/login",
            "/register",
            "/auth/login"
        ],
        llm_provider="none",
        enable_async=True,
    )

else:

    class Settings:
        def __init__(self):

            self.base_dir = Path(__file__).parent
            self.skills_dir = self.base_dir / "skills"
            self.tools_dir = self.base_dir / "tools"

            # execution
            self.execution_mode = "auto"
            self.max_iterations = 80

            self.tool_timeout = 30
            self.api_timeout = 5
            self.max_skill_execution_time = 60

            self.enable_async = True
            self.max_concurrent_tools = 6

            # pro safety controls
            self.target_mode = "normal"
            self.allow_ip_targets = False
            self.allow_private_networks = False

            self.auto_stop_on_high_risk = True
            self.auto_stop_threshold = 30.0
            self.soft_stop_findings_limit = 25

            # scoring
            self.severity_weights = {
                "low": 1,
                "medium": 3,
                "high": 7,
                "critical": 12
            }

            self.confidence_multiplier = 1.2
            self.exploitability_weight = 1.5

            self.tool_reliability = {
                "subfinder": 0.75,
                "nmap": 0.85,
                "nikto": 0.65
            }

            # skills
            self.skill_deps = {
                "recon": [],
                "exposure": ["recon"],
                "web_scan": ["exposure"],
                "api_scan": ["web_scan"],
                "api_tester": ["api_scan"],
                "inspector": ["recon", "exposure", "web_scan", "api_scan"],
                "report": ["recon", "exposure", "web_scan", "inspector"],
            }

            self.api_test_endpoints = [
                "/api",
                "/login",
                "/register",
                "/auth/login"
            ]

            # llm
            self.llm_provider = "none"
            self.llm_model = None
            self.llm_api_key = None
            self.llm_temperature = 0.3


settings = Settings()

# -----------------------------
# EXPORTS
# -----------------------------
SKILL_DEPS = settings.skill_deps
API_TEST_ENDPOINTS = settings.api_test_endpoints

TOOL_TIMEOUT = settings.tool_timeout
API_TIMEOUT = settings.api_timeout
MAX_SKILL_EXECUTION_TIME = settings.max_skill_execution_time
MAX_ITERATIONS = settings.max_iterations

EXECUTION_MODE = settings.execution_mode

SEVERITY_WEIGHTS = settings.severity_weights
CONFIDENCE_MULTIPLIER = settings.confidence_multiplier
EXPLOITABILITY_WEIGHT = settings.exploitability_weight

TOOL_RELIABILITY = settings.tool_reliability

ENABLE_ASYNC = settings.enable_async
MAX_CONCURRENT_TOOLS = settings.max_concurrent_tools

TARGET_MODE = settings.target_mode
ALLOW_IP_TARGETS = settings.allow_ip_targets
ALLOW_PRIVATE_NETWORKS = settings.allow_private_networks

AUTO_STOP_ON_HIGH_RISK = settings.auto_stop_on_high_risk
AUTO_STOP_THRESHOLD = settings.auto_stop_threshold
SOFT_STOP_LIMIT = settings.soft_stop_findings_limit

LLM_PROVIDER = settings.llm_provider
LLM_MODEL = settings.llm_model
LLM_API_KEY = settings.llm_api_key
LLM_TEMPERATURE = settings.llm_temperature

BASE_DIR = settings.base_dir
SKILLS_DIR = settings.skills_dir
TOOLS_DIR = settings.tools_dir

# Fix #2: VERBOSITY was imported in main.py and engine.py but never defined
VERBOSITY = int(os.getenv("VERBOSITY", "1"))  # 0=quiet, 1=normal, 2=verbose
