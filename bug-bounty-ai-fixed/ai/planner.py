"""AI planner — skill sequencing with dependency awareness."""
from __future__ import annotations
import logging
from typing import Optional, List, Tuple
from config import SKILL_DEPS
from core.context import Context
from core.registry import Registry

logger = logging.getLogger(__name__)

# (skill_name, priority, condition_fn)
_PLAN: List[Tuple[str, int, any]] = [
    ("recon",             10, lambda c: True),
    ("passive_recon",      9, lambda c: len(c.subdomains) > 0),
    ("exposure",           8, lambda c: len(c.subdomains) > 0),
    ("tech_fingerprint",   7, lambda c: len(c.subdomains) > 0),
    ("web_scan",           6, lambda c: len(c.subdomains) > 0),
    ("api_scan",           5, lambda c: len(c.subdomains) > 0),
    ("api_tester",         4, lambda c: len(c.endpoints) > 0),
    ("sqli_detect",        4, lambda c: len(c.subdomains) > 0),
    ("auth_test",          3, lambda c: len(c.subdomains) > 0),
    ("verify",             3, lambda c: len(c.all_findings()) > 0),
    ("inspector",          2, lambda c: len(c.all_findings()) > 0 or len(c.subdomains) > 0),
    ("poc_generator",      2, lambda c: len(c.all_findings()) > 0),
    ("report_submit",      1, lambda c: len(c.all_findings()) > 0),
    ("report",             1, lambda c: True),
]


def choose_skill(context: Context, registry: Registry) -> Optional[str]:
    executed = set(context.executed_skills)
    for name, _, cond in _PLAN:
        if name in executed or registry.get(name) is None:
            continue
        if not _deps_met(name, executed):
            continue
        try:
            if cond(context):
                logger.debug(f"Planner selected: {name}")
                return name
        except Exception:
            continue
    return "report"


def choose_skill_batch(context: Context, registry: Registry) -> List[str]:
    executed = set(context.executed_skills)
    candidates = []
    for name, priority, cond in _PLAN:
        if name in executed or registry.get(name) is None:
            continue
        if not _deps_met(name, executed):
            continue
        try:
            if cond(context):
                candidates.append((priority, name))
        except Exception:
            continue
    candidates.sort(reverse=True)
    return [n for _, n in candidates[:3]]


def _deps_met(skill: str, executed: set) -> bool:
    return all(d in executed for d in SKILL_DEPS.get(skill, []))
