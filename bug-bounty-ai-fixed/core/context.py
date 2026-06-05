"""Execution context — shared mutable state threaded through every skill."""

from __future__ import annotations

import time
from datetime import datetime
from typing import List, Dict, Any, Optional

from core.models import Finding, ProofMode


class Context:
    def __init__(self, target: str, proof_mode: ProofMode = ProofMode.ALL):
        self.target:      str       = target
        self.proof_mode:  ProofMode = proof_mode

        # Asset discovery
        self.subdomains: List[str] = []
        self.endpoints:  List[str] = []
        self.services:   List[str] = []

        # Findings — always List[Finding]
        self._findings: List[Finding] = []

        # Structured insights
        self.insights: List[Dict[str, Any]] = []

        # Execution tracking
        self.errors:          List[Dict[str, str]] = []
        self.executed_skills: List[str] = []
        self.skipped_skills:  List[str] = []

        self.start_time:  float = time.time()
        self.tool_status: Dict[str, bool] = {}

        self.metadata: Dict[str, Any] = {
            "created_at":        datetime.now().isoformat(),
            "execution_history": [],
            "proof_mode":        proof_mode.value,
        }
        self.report: Dict[str, Any] = {}

    # ── findings interface ───────────────────────────────────────────────────

    @property
    def findings(self) -> List[Finding]:
        """Return findings filtered by proof_mode."""
        if self.proof_mode == ProofMode.ALL:
            return self._findings
        if self.proof_mode == ProofMode.PROOF_ONLY:
            return [f for f in self._findings if f.is_verified]
        if self.proof_mode == ProofMode.HIGH_AND_ABOVE:
            from core.models import Severity
            return [
                f for f in self._findings
                if f.effective_severity < Severity.HIGH or f.is_verified
            ]
        return self._findings

    @findings.setter
    def findings(self, value: List[Finding]) -> None:
        self._findings = value

    def add_finding(self, finding: Finding) -> None:
        if not isinstance(finding, Finding):
            raise TypeError(f"Expected Finding, got {type(finding).__name__}")
        # Deduplicate on (title, target, category)
        for existing in self._findings:
            if (existing.title == finding.title and
                    existing.target == finding.target and
                    existing.category == finding.category):
                return
        self._findings.append(finding)

    def all_findings(self) -> List[Finding]:
        """All findings regardless of proof_mode — for internal use."""
        return self._findings

    # ── execution tracking ───────────────────────────────────────────────────

    def add_execution(self, skill: str, duration: float, success: bool) -> None:
        self.metadata["execution_history"].append({
            "skill":     skill,
            "duration":  round(duration, 3),
            "success":   success,
            "timestamp": datetime.now().isoformat(),
        })

    def add_error(self, skill: str, error: str) -> None:
        entry = {"skill": skill, "error": error}
        if entry not in self.errors:
            self.errors.append(entry)

    def get_execution_time(self) -> float:
        return time.time() - self.start_time

    def __repr__(self) -> str:
        return (
            f"Context(target={self.target!r}, "
            f"subdomains={len(self.subdomains)}, "
            f"findings={len(self._findings)}, "
            f"verified={sum(1 for f in self._findings if f.is_verified)}, "
            f"proof_mode={self.proof_mode.value})"
        )
