"""Report skill — build structured summary on context.report."""

from __future__ import annotations

import logging
from collections import Counter

from core.context import Context
from core.models import Severity

logger = logging.getLogger(__name__)


def run(context: Context) -> Context:
    sev_counts: Counter = Counter(f.severity.value for f in context.findings)
    risk_score = sum(f.severity.weight * f.confidence for f in context.findings)

    risk_level = (
        Severity.CRITICAL if risk_score > 40 else
        Severity.HIGH     if risk_score > 20 else
        Severity.MEDIUM   if risk_score > 8  else
        Severity.LOW
    )

    context.report = {
        "target":      context.target,
        "risk_score":  round(risk_score, 2),
        "risk_level":  risk_level.value,
        "findings": {
            "total":    len(context.findings),
            "by_severity": dict(sev_counts),
        },
        "attack_surface": {
            "subdomains": len(context.subdomains),
            "services":   len(context.services),
            "endpoints":  len(context.endpoints),
        },
        "execution": {
            "skills_executed": context.executed_skills,
            "skills_skipped":  context.skipped_skills,
            "time_s":          round(context.get_execution_time(), 2),
        },
    }

    logger.info(f"Report built — risk {risk_level.value.upper()} (score {risk_score:.1f})")
    return context


skill = {"name": "report", "run": run}
