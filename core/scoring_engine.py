"""
ScoringEngine — CVSS-aware risk scoring.

Formula
-------
  If finding has a CvssVector:   score = cvss.score × confidence
  Otherwise (heuristic):         score = severity.weight × exploitability × confidence

Exploitability is derived from category + title keywords.
All scoring is in-place on Finding.score — no wrapper types.
"""

from __future__ import annotations

import logging
from typing import List

from core.models import Finding, FindingCategory

logger = logging.getLogger(__name__)

_CATEGORY_EXPLOIT: dict[FindingCategory, float] = {
    FindingCategory.INJECTION:     1.5,
    FindingCategory.AUTH:          1.4,
    FindingCategory.MISCONFIGURED: 1.3,
    FindingCategory.API:           1.2,
    FindingCategory.EXPOSURE:      1.1,
    FindingCategory.WEB:           1.0,
    FindingCategory.CRYPTO:        1.0,
    FindingCategory.INFO_LEAK:     0.9,
    FindingCategory.OTHER:         0.8,
    FindingCategory.RECON:         0.6,
}

_KEYWORD_BOOSTS: list[tuple[list[str], float]] = [
    (["rce", "remote code", "command injection"],       1.5),
    (["sql injection", "sqli"],                         1.4),
    (["ssrf"],                                          1.4),
    (["auth bypass", "authentication bypass"],          1.4),
    (["lfi", "path traversal", "directory traversal"],  1.3),
    (["xxe"],                                           1.3),
    (["insecure deserialization"],                      1.3),
    (["xss", "cross-site scripting"],                   1.2),
    (["open redirect"],                                 1.1),
    (["exposed credentials", "hardcoded secret"],       1.5),
    (["version disclosure", "technology disclosure"],   0.7),
    (["missing header", "security header"],             0.8),
]


class ScoringEngine:
    def score_all(self, findings: List[Finding]) -> List[Finding]:
        for f in findings:
            f.score = self._score(f)
        findings.sort(key=lambda f: f.score, reverse=True)
        return findings

    def _score(self, f: Finding) -> float:
        conf = max(0.0, min(1.0, f.confidence))
        if f.cvss is not None:
            # CVSS score is already 0–10; scale to match heuristic range
            return round(f.cvss.score * conf, 3)
        base   = f.effective_severity.weight
        exploit = self._exploitability(f)
        return round(base * exploit * conf, 3)

    def _exploitability(self, f: Finding) -> float:
        factor = _CATEGORY_EXPLOIT.get(f.category, 0.8)
        title  = f.title.lower()
        best   = max(
            (boost for kws, boost in _KEYWORD_BOOSTS if any(k in title for k in kws)),
            default=None,
        )
        if best is not None:
            factor = factor * 0.6 + best * 0.4
        return factor
