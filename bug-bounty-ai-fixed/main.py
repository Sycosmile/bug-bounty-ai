"""bug-bounty-ai — autonomous security analysis tool"""

import argparse
import logging
import sys

from config import VERBOSITY
from core.context import Context
from core.engine import Engine
from core.loader import load_skills
from core.models import ProofMode, Severity
from core.registry import Registry
from core.tool_checker import check_tools
from reports.exporter import export_all
from utils.validator import validate_target

logging.basicConfig(
    level=logging.DEBUG if VERBOSITY >= 2 else logging.INFO,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
)
logger = logging.getLogger(__name__)


# ─────────────────────────────────────────────────────────────────────────────
# CLI
# ─────────────────────────────────────────────────────────────────────────────

def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(description="bug-bounty-ai autonomous scanner")
    p.add_argument("target", nargs="?", help="Target URL or IP (prompted if omitted)")
    p.add_argument(
        "--proof-mode",
        choices=["all", "proof_only", "high_and_above"],
        default="all",
        help=(
            "all            — emit all findings (default)\n"
            "proof_only     — only emit findings with confirmed proof\n"
            "high_and_above — proof required for HIGH/CRITICAL; all others pass"
        ),
    )
    p.add_argument("--no-export", action="store_true", help="Skip writing report files")
    return p.parse_args()


# ─────────────────────────────────────────────────────────────────────────────
# Report formatter
# ─────────────────────────────────────────────────────────────────────────────

def format_report(context: Context) -> str:
    findings  = context.findings          # respects proof_mode
    all_f     = context.all_findings()
    verified  = sum(1 for f in all_f if f.is_verified)
    suppressed = len(all_f) - len(findings)

    sep = "=" * 70
    lines = [
        sep,
        "                   BUG BOUNTY ANALYSIS REPORT",
        sep,
        f"Target:                   {context.target}",
        f"Analysis Time:            {context.get_execution_time():.2f}s",
        f"Proof Mode:               {context.proof_mode.value}",
        "",
        f"Skills Executed:          {len(context.executed_skills)}",
        f"Skills Skipped:           {len(context.skipped_skills)}",
        "",
        "RECON RESULTS:",
        f"  Subdomains Found:       {len(context.subdomains)}",
        f"  Services Found:         {len(context.services)}",
        f"  Endpoints Found:        {len(context.endpoints)}",
        "",
        "FINDINGS:",
        f"  Total (visible):        {len(findings)}",
        f"  Verified:               {verified}/{len(all_f)}",
    ]
    if suppressed:
        lines.append(f"  Suppressed by proof mode: {suppressed}")

    # severity breakdown
    for sev in reversed(list(Severity)):
        n = sum(1 for f in findings if f.effective_severity == sev)
        if n:
            lines.append(f"  {sev.value.capitalize():<10}             {n}")

    if context.report:
        lines += [
            "",
            f"  Risk Score:             {context.report.get('risk_score', '—')}",
            f"  Risk Level:             {context.report.get('risk_level', '—').upper()}",
        ]

    lines += [
        "",
        f"ERRORS:  {len(context.errors)}",
        "",
        sep,
        "DETAILED FINDINGS:",
    ]

    if findings:
        for i, f in enumerate(findings, 1):
            cvss_str  = f" CVSS:{f.cvss.score}" if f.cvss else ""
            score_str = f" [score:{f.score:.2f}]" if f.score else ""
            conf_str  = f" [conf:{f.confidence:.0%}]"
            verified_str = " ✓" if f.is_verified else ""
            lines.append(
                f"  {i:>2}. [{f.effective_severity.value.upper()}{cvss_str}]"
                f"{score_str}{conf_str}{verified_str} {f.title}"
            )
            lines.append(f"      → {f.target}")
            if f.proof.is_verified if hasattr(f.proof, 'is_verified') else f.proof.verified:
                lines.append(f"      ✓ Proof: {f.proof.method}")
            if VERBOSITY >= 1 and f.remediation:
                lines.append(f"      ⚑ Fix: {f.remediation[:120]}")
    else:
        lines.append("  No findings detected.")

    lines.append(sep)
    return "\n".join(lines)


# ─────────────────────────────────────────────────────────────────────────────
# Main
# ─────────────────────────────────────────────────────────────────────────────

def main() -> int:
    args = parse_args()

    # ── tool status ──────────────────────────────────────────────────────────
    tool_status = check_tools()
    print("\n🔧 TOOL STATUS")
    for tool, available in tool_status.items():
        status = "✓ Installed" if available else "✗ Missing"
        print(f"  {tool}: {status}")

    # ── skill loading ────────────────────────────────────────────────────────
    registry = Registry()
    load_skills(registry)
    skill_names = registry.list_skills()
    if not skill_names:
        print("✗ No skills loaded — aborting")
        return 1
    print(f"\n✓ Loaded {len(skill_names)} skills")

    # ── target ───────────────────────────────────────────────────────────────
    target = args.target or input("\n🎯 Target domain: ").strip()
    if not validate_target(target):
        print(f"✗ Invalid or disallowed target: {target}")
        return 1
    print(f"✓ Ready to analyze: {target}")

    # ── proof mode ───────────────────────────────────────────────────────────
    proof_mode = ProofMode(args.proof_mode)
    if proof_mode != ProofMode.ALL:
        print(f"🔒 Proof mode: {proof_mode.value} — unverified findings will be suppressed")

    # ── run ──────────────────────────────────────────────────────────────────
    print("\n🚀 Starting analysis...")
    logger.info(f"Target: {target}")

    context = Context(target=target, proof_mode=proof_mode)
    context.tool_status = tool_status

    engine = Engine(registry)
    result = engine.run(context)

    # ── report ───────────────────────────────────────────────────────────────
    print(format_report(result))

    if not args.no_export:
        try:
            paths = export_all(result)
            print("📁 Reports saved:")
            print(f"   JSON → {paths['json']}")
            print(f"   HTML → {paths['html']}")
        except Exception as e:
            logger.warning(f"Export failed: {e}")
            print(f"⚠️  Could not save report files: {e}")

    logger.info(f"Analysis completed for {target}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
