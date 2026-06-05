"""
Central vulnerability scoring engine
Converts findings into risk scores and overall system risk
"""

from core.models import Finding


class ScoringEngine:
    """Computes risk score from structured findings"""

    def __init__(self):
        # weight per severity
        self.weights = {
            "critical": 10,
            "high": 7,
            "medium": 4,
            "low": 2,
            "info": 1
        }

    def score_finding(self, finding: Finding) -> int:
        """Score a single finding"""
        return self.weights.get(finding.severity, 0)

    def score_all(self, findings: list[Finding]) -> int:
        """Compute total risk score"""
        return sum(self.score_finding(f) for f in findings)

    def severity_breakdown(self, findings: list[Finding]) -> dict:
        """Count findings per severity level"""
        breakdown = {
            "critical": 0,
            "high": 0,
            "medium": 0,
            "low": 0,
            "info": 0
        }

        for f in findings:
            if f.severity in breakdown:
                breakdown[f.severity] += 1

        return breakdown

    def risk_level(self, score: int) -> str:
        """Convert numeric score to human risk level"""
        if score >= 40:
            return "CRITICAL"
        elif score >= 25:
            return "HIGH"
        elif score >= 10:
            return "MEDIUM"
        else:
            return "LOW"

    def build_risk_report(self, findings: list[Finding]) -> dict:
        """Full risk intelligence report"""
        score = self.score_all(findings)

        return {
            "total_score": score,
            "risk_level": self.risk_level(score),
            "severity_breakdown": self.severity_breakdown(findings)
        }
