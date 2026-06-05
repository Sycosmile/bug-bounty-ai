"""
Core domain models for bug-bounty-ai.

Architecture
------------
Finding         — single canonical vulnerability object (no parallel types)
Severity        — enum with CVSS-aligned numeric weights + ordering
FindingCategory — OWASP-aligned category enum
CvssVector      — CVSS 3.1 base-metric dataclass; computes numeric score
Proof           — structured evidence object attached to every verified finding
ProofMode       — controls whether unverified findings are accepted
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import List, Optional


# ─────────────────────────────────────────────────────────────────────────────
# Severity
# ─────────────────────────────────────────────────────────────────────────────

class Severity(str, Enum):
    """CVSS-aligned severity levels.
    String subclass — serialises without .value everywhere.
    """
    INFO     = "info"
    LOW      = "low"
    MEDIUM   = "medium"
    HIGH     = "high"
    CRITICAL = "critical"

    @property
    def weight(self) -> float:
        """Numeric weight for risk-score formula."""
        return {
            Severity.INFO:     0.0,
            Severity.LOW:      1.0,
            Severity.MEDIUM:   3.0,
            Severity.HIGH:     7.0,
            Severity.CRITICAL: 12.0,
        }[self]

    @property
    def _rank(self) -> int:
        return {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}[self.value]

    def __lt__(self, other: "Severity") -> bool: return self._rank < other._rank
    def __le__(self, other: "Severity") -> bool: return self._rank <= other._rank
    def __gt__(self, other: "Severity") -> bool: return self._rank > other._rank
    def __ge__(self, other: "Severity") -> bool: return self._rank >= other._rank

    @classmethod
    def from_str(cls, value: str) -> "Severity":
        try:
            return cls(value.lower().strip())
        except ValueError:
            return cls.INFO

    @classmethod
    def from_cvss(cls, cvss_score: float) -> "Severity":
        """Map a CVSS 3.1 numeric score to a Severity bucket."""
        if cvss_score >= 9.0:  return cls.CRITICAL
        if cvss_score >= 7.0:  return cls.HIGH
        if cvss_score >= 4.0:  return cls.MEDIUM
        if cvss_score >= 0.1:  return cls.LOW
        return cls.INFO


# ─────────────────────────────────────────────────────────────────────────────
# Finding categories
# ─────────────────────────────────────────────────────────────────────────────

class FindingCategory(str, Enum):
    RECON         = "recon"
    EXPOSURE      = "exposure"
    WEB           = "web"
    API           = "api"
    INJECTION     = "injection"
    AUTH          = "auth"
    CRYPTO        = "crypto"
    MISCONFIGURED = "misconfigured"
    INFO_LEAK     = "info_leak"
    OTHER         = "other"


# ─────────────────────────────────────────────────────────────────────────────
# CVSS 3.1 base vector
# ─────────────────────────────────────────────────────────────────────────────

class CvssAV(str, Enum):
    NETWORK   = "N"
    ADJACENT  = "A"
    LOCAL     = "L"
    PHYSICAL  = "P"

class CvssAC(str, Enum):
    LOW  = "L"
    HIGH = "H"

class CvssPR(str, Enum):
    NONE     = "N"
    LOW      = "L"
    HIGH     = "H"

class CvssUI(str, Enum):
    NONE     = "N"
    REQUIRED = "R"

class CvssScope(str, Enum):
    UNCHANGED = "U"
    CHANGED   = "C"

class CvssImpact(str, Enum):
    NONE = "N"
    LOW  = "L"
    HIGH = "H"


@dataclass
class CvssVector:
    """
    CVSS 3.1 Base Score calculator.
    All fields use the enum classes above for type safety.

    Usage:
        v = CvssVector(AV=CvssAV.NETWORK, AC=CvssAC.LOW, PR=CvssPR.NONE,
                       UI=CvssUI.NONE, S=CvssScope.UNCHANGED,
                       C=CvssImpact.HIGH, I=CvssImpact.HIGH, A=CvssImpact.HIGH)
        print(v.score)   # 9.8
        print(v.vector_string)  # "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
    """
    AV: CvssAV    = CvssAV.NETWORK
    AC: CvssAC    = CvssAC.LOW
    PR: CvssPR    = CvssPR.NONE
    UI: CvssUI    = CvssUI.NONE
    S:  CvssScope = CvssScope.UNCHANGED
    C:  CvssImpact = CvssImpact.NONE
    I:  CvssImpact = CvssImpact.NONE
    A:  CvssImpact = CvssImpact.NONE

    # ── score computation ────────────────────────────────────────────────────

    @property
    def score(self) -> float:
        """Compute CVSS 3.1 base score (0.0–10.0)."""
        ISS  = self._impact_sub_score()
        if ISS == 0:
            return 0.0
        impact = self._impact(ISS)
        exploit = self._exploitability()
        if self.S == CvssScope.UNCHANGED:
            raw = min(impact + exploit, 10.0)
        else:
            raw = min(1.08 * (impact + exploit), 10.0)
        return self._roundup(raw)

    @property
    def severity(self) -> Severity:
        return Severity.from_cvss(self.score)

    @property
    def vector_string(self) -> str:
        return (
            f"CVSS:3.1/AV:{self.AV.value}/AC:{self.AC.value}"
            f"/PR:{self.PR.value}/UI:{self.UI.value}"
            f"/S:{self.S.value}/C:{self.C.value}/I:{self.I.value}/A:{self.A.value}"
        )

    # ── internal helpers ─────────────────────────────────────────────────────

    _AV_W  = {CvssAV.NETWORK: 0.85, CvssAV.ADJACENT: 0.62, CvssAV.LOCAL: 0.55, CvssAV.PHYSICAL: 0.2}
    _AC_W  = {CvssAC.LOW: 0.77, CvssAC.HIGH: 0.44}
    _PR_W_U = {CvssPR.NONE: 0.85, CvssPR.LOW: 0.62, CvssPR.HIGH: 0.27}
    _PR_W_C = {CvssPR.NONE: 0.85, CvssPR.LOW: 0.68, CvssPR.HIGH: 0.50}
    _UI_W  = {CvssUI.NONE: 0.85, CvssUI.REQUIRED: 0.62}
    _IMP_W = {CvssImpact.NONE: 0.0, CvssImpact.LOW: 0.22, CvssImpact.HIGH: 0.56}

    def _impact_sub_score(self) -> float:
        return 1 - (
            (1 - self._IMP_W[self.C]) *
            (1 - self._IMP_W[self.I]) *
            (1 - self._IMP_W[self.A])
        )

    def _impact(self, ISS: float) -> float:
        if self.S == CvssScope.UNCHANGED:
            return 6.42 * ISS
        return 7.52 * (ISS - 0.029) - 3.25 * ((ISS - 0.02) ** 15)

    def _exploitability(self) -> float:
        pr_w = (self._PR_W_C if self.S == CvssScope.CHANGED else self._PR_W_U)[self.PR]
        return 8.22 * self._AV_W[self.AV] * self._AC_W[self.AC] * pr_w * self._UI_W[self.UI]

    @staticmethod
    def _roundup(x: float) -> float:
        """CVSS 3.1 roundup: ceil to 1 decimal."""
        import math
        return math.ceil(x * 10) / 10


# ─────────────────────────────────────────────────────────────────────────────
# Proof — structured evidence for verified findings
# ─────────────────────────────────────────────────────────────────────────────

@dataclass
class Proof:
    """
    Structured evidence that a finding was confirmed, not just suspected.

    verified       : True = exploit/confirmation engine confirmed this
    method         : How it was confirmed (e.g. "iframe_render", "port_open")
    request        : The HTTP request (or command) used to confirm
    response       : The response / output that constitutes proof
    screenshot_b64 : Optional base64-encoded PNG (for visual confirmations)
    """
    verified:       bool  = False
    method:         str   = ""
    request:        str   = ""
    response:       str   = ""
    screenshot_b64: str   = ""

    def to_dict(self) -> dict:
        return {
            "verified":   self.verified,
            "method":     self.method,
            "request":    self.request,
            "response":   self.response[:2000],          # truncate for reports
            "has_screenshot": bool(self.screenshot_b64),
        }


# ─────────────────────────────────────────────────────────────────────────────
# ProofMode — controls finding acceptance policy
# ─────────────────────────────────────────────────────────────────────────────

class ProofMode(str, Enum):
    """
    ALL           : Accept all findings regardless of verification status
    PROOF_ONLY    : Only emit findings that have proof.verified == True
    HIGH_AND_ABOVE: PROOF_ONLY for HIGH/CRITICAL; ALL for lower severities
    """
    ALL            = "all"
    PROOF_ONLY     = "proof_only"
    HIGH_AND_ABOVE = "high_and_above"


# ─────────────────────────────────────────────────────────────────────────────
# Canonical Finding
# ─────────────────────────────────────────────────────────────────────────────

@dataclass
class Finding:
    """
    Single canonical vulnerability object.

    Required fields
    ---------------
    title      : ≤ 120 char human-readable label
    severity   : Severity enum
    category   : FindingCategory enum
    source     : producing skill/tool name
    target     : exact URL / host:port tested

    Optional enrichment
    --------------------
    description : extended explanation
    remediation : actionable fix
    confidence  : 0.0–1.0 subjective confidence
    evidence    : raw proof string (deprecated — prefer proof.response)
    cve         : CVE identifier
    references  : advisory / OWASP URLs
    cvss        : CvssVector instance — when set, severity derives from it
    proof       : Proof instance — populated by verify/ modules

    Computed
    --------
    score       : set by ScoringEngine; skills must NOT set this
    """

    # Required
    title:    str
    severity: Severity
    category: FindingCategory
    source:   str
    target:   str

    # Enrichment
    description: str           = ""
    remediation: str           = ""
    confidence:  float         = 0.8
    evidence:    str           = ""
    cve:         Optional[str] = None
    references:  List[str]     = field(default_factory=list)

    # Structured scoring / proof
    cvss:  Optional[CvssVector] = field(default=None, compare=False)
    proof: Proof                = field(default_factory=Proof, compare=False)

    # Set by ScoringEngine
    score: float = field(default=0.0, compare=False)

    # ── helpers ──────────────────────────────────────────────────────────────

    @property
    def effective_severity(self) -> Severity:
        """If a CVSS vector is attached, let it override severity."""
        if self.cvss is not None:
            return self.cvss.severity
        return self.severity

    @property
    def is_verified(self) -> bool:
        return self.proof.verified

    def to_dict(self) -> dict:
        return {
            "title":             self.title,
            "severity":          self.effective_severity.value,
            "category":          self.category.value,
            "source":            self.source,
            "target":            self.target,
            "description":       self.description,
            "remediation":       self.remediation,
            "confidence":        round(self.confidence, 3),
            "evidence":          self.evidence,
            "cve":               self.cve,
            "references":        self.references,
            "cvss_score":        round(self.cvss.score, 1) if self.cvss else None,
            "cvss_vector":       self.cvss.vector_string if self.cvss else None,
            "proof":             self.proof.to_dict(),
            "verified":          self.is_verified,
            "score":             round(self.score, 3),
        }

    def __str__(self) -> str:
        verified = " ✓VERIFIED" if self.is_verified else ""
        cvss_str = f" CVSS:{self.cvss.score}" if self.cvss else ""
        return f"[{self.effective_severity.value.upper()}{cvss_str}]{verified} {self.title} ({self.target})"
