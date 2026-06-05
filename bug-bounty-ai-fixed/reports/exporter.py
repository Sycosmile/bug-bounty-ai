"""Export bug bounty findings to JSON and HTML reports"""

import json
import re
import logging
from datetime import datetime
from pathlib import Path
from core.context import Context

logger = logging.getLogger(__name__)

OUTPUT_DIR = Path("output")


def _ensure_output_dir() -> Path:
    OUTPUT_DIR.mkdir(exist_ok=True)
    return OUTPUT_DIR


def _safe_filename(target: str) -> str:
    """Turn a target URL into a safe filename stem"""
    stem = re.sub(r"^https?://", "", target).rstrip("/")
    stem = re.sub(r"[^\w\-.]", "_", stem)
    return stem


def _finding_to_dict(f) -> dict:
    """Normalise a Finding to a plain dict for serialisation."""
    if hasattr(f, "to_dict"):
        return f.to_dict()
    if isinstance(f, dict):
        return f
    return {"title": str(f), "severity": "info", "category": "other",
            "source": "", "target": "", "score": 0.0, "confidence": 0.0}


def _severity_color(sev: str) -> str:
    return {
        "critical": "#c0392b",
        "high":     "#e67e22",
        "medium":   "#f1c40f",
        "low":      "#27ae60",
        "info":     "#2980b9",
    }.get(sev.lower(), "#95a5a6")


def _severity_badge_class(sev: str) -> str:
    return {
        "critical": "badge-critical",
        "high":     "badge-high",
        "medium":   "badge-medium",
        "low":      "badge-low",
        "info":     "badge-info",
    }.get(sev.lower(), "badge-info")


def _build_summary(findings: list[dict]) -> dict:
    counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    risk_score = 0
    weights = {"critical": 12, "high": 7, "medium": 3, "low": 1, "info": 0}
    for f in findings:
        sev = f.get("severity", "info").lower()
        counts[sev] = counts.get(sev, 0) + 1
        risk_score += weights.get(sev, 0)
    level = (
        "CRITICAL" if risk_score > 40 else
        "HIGH"     if risk_score > 25 else
        "MEDIUM"   if risk_score > 10 else
        "LOW"
    )
    return {"counts": counts, "risk_score": risk_score, "risk_level": level}


# ─────────────────────────────────────────────
# JSON EXPORT
# ─────────────────────────────────────────────

def export_json(context: Context) -> Path:
    """Write full findings to a JSON file and return the path"""
    out_dir = _ensure_output_dir()
    stem = _safe_filename(context.target)
    ts   = datetime.now().strftime("%Y%m%d_%H%M%S")
    path = out_dir / f"{stem}_{ts}.json"

    findings = [_finding_to_dict(f) for f in context.findings]
    summary  = _build_summary(findings)

    payload = {
        "meta": {
            "tool":       "bug-bounty-ai",
            "target":     context.target,
            "generated":  datetime.now().isoformat(),
            "analysis_time_s": round(context.get_execution_time(), 2),
        },
        "summary": summary,
        "attack_surface": {
            "subdomains": context.subdomains,
            "services":   context.services,
            "endpoints":  context.endpoints,
        },
        "findings": findings,
        "insights": context.insights,
        "execution": {
            "skills_executed": context.executed_skills,
            "skills_skipped":  context.skipped_skills,
            "errors":          context.errors,
            "history":         context.metadata.get("execution_history", []),
        },
    }

    path.write_text(json.dumps(payload, indent=2, default=str), encoding="utf-8")
    logger.info(f"JSON report saved: {path}")
    return path


# ─────────────────────────────────────────────
# HTML EXPORT
# ─────────────────────────────────────────────

def export_html(context: Context) -> Path:
    """Write a styled HTML report and return the path"""
    out_dir = _ensure_output_dir()
    stem = _safe_filename(context.target)
    ts   = datetime.now().strftime("%Y%m%d_%H%M%S")
    path = out_dir / f"{stem}_{ts}.html"

    findings = [_finding_to_dict(f) for f in context.findings]
    summary  = _build_summary(findings)
    generated = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    # ── severity gauge bar ──────────────────────────────────────────────────
    total = max(len(findings), 1)
    gauge_html = ""
    for sev in ["critical", "high", "medium", "low", "info"]:
        n = summary["counts"].get(sev, 0)
        if n:
            pct = n / total * 100
            gauge_html += (
                f'<div class="gauge-segment" style="width:{pct:.1f}%;'
                f'background:{_severity_color(sev)}" '
                f'title="{sev.capitalize()}: {n}"></div>'
            )

    # ── findings rows ────────────────────────────────────────────────────────
    rows_html = ""
    for i, f in enumerate(findings, 1):
        sev      = f.get("severity", "info").lower()
        title    = f.get("title", "—")
        target   = f.get("target", "—")
        source   = f.get("source", "—")
        conf     = f.get("confidence", 0.0)
        score    = f.get("score", 0.0)
        cvss     = f.get("cvss_score")
        verified = f.get("verified", False)
        conf_str  = f"{conf:.0%}"  if isinstance(conf, float) else str(conf)
        score_str = f"{score:.2f}" if isinstance(score, float) else str(score)
        cvss_str  = f"<br><small style='color:#8b949e'>CVSS {cvss}</small>" if cvss else ""
        v_badge   = '<span class="verified-badge">✓</span>' if verified else ""
        badge = f'<span class="badge {_severity_badge_class(sev)}">{sev.upper()}</span>'
        rows_html += f"""
        <tr>
          <td class="num">{i}</td>
          <td>{badge}{cvss_str}</td>
          <td class="title-cell">{title} {v_badge}</td>
          <td><code>{target}</code></td>
          <td>{source}</td>
          <td class="center">{conf_str}</td>
          <td class="center">{score_str}</td>
        </tr>"""
    # ── endpoints list ───────────────────────────────────────────────────────
    endpoints_html = "".join(
        f"<li><code>{e}</code></li>" for e in context.endpoints
    ) or "<li><em>None discovered</em></li>"

    # ── services list ────────────────────────────────────────────────────────
    services_html = "".join(
        f"<li><code>{s}</code></li>" for s in context.services
    ) or "<li><em>None discovered</em></li>"

    # ── subdomains list ──────────────────────────────────────────────────────
    subdomains_html = "".join(
        f"<li><code>{s}</code></li>" for s in context.subdomains
    ) or "<li><em>None discovered</em></li>"

    # ── risk level badge ─────────────────────────────────────────────────────
    rl  = summary["risk_level"]
    rl_color = _severity_color(rl.lower())

    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Bug Bounty Report — {context.target}</title>
<style>
  *, *::before, *::after {{ box-sizing: border-box; margin: 0; padding: 0; }}
  body {{ font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
         background: #0d1117; color: #c9d1d9; line-height: 1.6; }}
  a {{ color: #58a6ff; }}

  /* ── layout ── */
  .container {{ max-width: 1200px; margin: 0 auto; padding: 32px 24px; }}

  /* ── header ── */
  header {{ border-bottom: 1px solid #21262d; padding-bottom: 24px; margin-bottom: 32px; }}
  header h1 {{ font-size: 1.6rem; color: #f0f6fc; }}
  header .sub {{ color: #8b949e; font-size: 0.9rem; margin-top: 4px; }}
  .target-pill {{ display: inline-block; background: #161b22; border: 1px solid #30363d;
                  border-radius: 20px; padding: 4px 14px; font-family: monospace;
                  font-size: 0.9rem; margin-top: 10px; color: #79c0ff; }}

  /* ── cards ── */
  .cards {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(160px, 1fr));
            gap: 16px; margin-bottom: 32px; }}
  .card {{ background: #161b22; border: 1px solid #21262d; border-radius: 10px;
           padding: 20px 16px; text-align: center; }}
  .card .val {{ font-size: 2rem; font-weight: 700; color: #f0f6fc; }}
  .card .lbl {{ font-size: 0.78rem; color: #8b949e; margin-top: 4px; text-transform: uppercase; letter-spacing: .05em; }}
  .risk-card .val {{ color: {rl_color}; }}

  /* ── gauge ── */
  .gauge-wrap {{ margin-bottom: 32px; }}
  .gauge-wrap h2 {{ font-size: 1rem; color: #8b949e; margin-bottom: 10px; text-transform: uppercase; letter-spacing: .06em; }}
  .gauge {{ display: flex; height: 14px; border-radius: 7px; overflow: hidden; background: #21262d; }}
  .gauge-segment {{ height: 100%; transition: width .3s; }}
  .legend {{ display: flex; gap: 16px; margin-top: 8px; flex-wrap: wrap; }}
  .legend-item {{ display: flex; align-items: center; gap: 6px; font-size: 0.8rem; color: #8b949e; }}
  .legend-dot {{ width: 10px; height: 10px; border-radius: 50%; }}

  /* ── section ── */
  .section {{ margin-bottom: 36px; }}
  .section h2 {{ font-size: 1rem; color: #8b949e; text-transform: uppercase;
                 letter-spacing: .06em; margin-bottom: 14px;
                 padding-bottom: 8px; border-bottom: 1px solid #21262d; }}

  /* ── table ── */
  .tbl-wrap {{ overflow-x: auto; }}
  table {{ width: 100%; border-collapse: collapse; font-size: 0.875rem; }}
  th {{ background: #161b22; color: #8b949e; font-weight: 600; padding: 10px 12px;
        text-align: left; border-bottom: 1px solid #21262d; white-space: nowrap; }}
  td {{ padding: 10px 12px; border-bottom: 1px solid #161b22; vertical-align: top; }}
  tr:last-child td {{ border-bottom: none; }}
  tr:hover td {{ background: #161b22; }}
  td.num {{ color: #484f58; width: 36px; }}
  td.center {{ text-align: center; }}
  td.title-cell {{ max-width: 320px; word-break: break-word; color: #f0f6fc; }}
  code {{ background: #0d1117; border: 1px solid #21262d; border-radius: 4px;
          padding: 2px 6px; font-size: 0.82rem; color: #79c0ff;
          word-break: break-all; }}

  /* ── badges ── */
  .badge {{ display: inline-block; padding: 2px 8px; border-radius: 12px;
            font-size: 0.72rem; font-weight: 700; letter-spacing: .04em; }}
  .badge-critical {{ background: #3d0b0b; color: #ff7b72; border: 1px solid #c0392b; }}
  .badge-high     {{ background: #2d1b00; color: #ffa657; border: 1px solid #e67e22; }}
  .badge-medium   {{ background: #2d2200; color: #e3b341; border: 1px solid #f1c40f; }}
  .badge-low      {{ background: #0b2a18; color: #56d364; border: 1px solid #27ae60; }}
  .badge-info     {{ background: #051d38; color: #58a6ff; border: 1px solid #2980b9; }}

  /* ── surface lists ── */
  .surface-grid {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(280px, 1fr)); gap: 20px; }}
  .surface-box {{ background: #161b22; border: 1px solid #21262d; border-radius: 8px; padding: 16px; }}
  .surface-box h3 {{ font-size: 0.82rem; color: #8b949e; text-transform: uppercase;
                     letter-spacing: .06em; margin-bottom: 10px; }}
  .surface-box ul {{ list-style: none; display: flex; flex-direction: column; gap: 6px; }}
  .surface-box li code {{ display: block; }}

  /* ── footer ── */
  footer {{ border-top: 1px solid #21262d; padding-top: 20px; margin-top: 40px;
            font-size: 0.8rem; color: #484f58; text-align: center; }}
</style>
</head>
<body>
<div class="container">

  <header>
    <h1>🔍 Bug Bounty Analysis Report</h1>
    <div class="sub">Generated {generated}</div>
    <div class="target-pill">{context.target}</div>
  </header>

  <!-- ── summary cards ── -->
  <div class="cards">
    <div class="card risk-card">
      <div class="val">{rl}</div>
      <div class="lbl">Risk Level</div>
    </div>
    <div class="card">
      <div class="val" style="color:#f0f6fc">{summary["risk_score"]}</div>
      <div class="lbl">Risk Score</div>
    </div>
    <div class="card">
      <div class="val" style="color:#ff7b72">{summary["counts"]["critical"]}</div>
      <div class="lbl">Critical</div>
    </div>
    <div class="card">
      <div class="val" style="color:#ffa657">{summary["counts"]["high"]}</div>
      <div class="lbl">High</div>
    </div>
    <div class="card">
      <div class="val" style="color:#e3b341">{summary["counts"]["medium"]}</div>
      <div class="lbl">Medium</div>
    </div>
    <div class="card">
      <div class="val" style="color:#56d364">{summary["counts"]["low"]}</div>
      <div class="lbl">Low</div>
    </div>
    <div class="card">
      <div class="val" style="color:#8b949e">{len(context.executed_skills)}</div>
      <div class="lbl">Skills Run</div>
    </div>
    <div class="card">
      <div class="val" style="color:#8b949e">{context.get_execution_time():.0f}s</div>
      <div class="lbl">Scan Time</div>
    </div>
  </div>

  <!-- ── gauge ── -->
  <div class="gauge-wrap">
    <h2>Severity Distribution</h2>
    <div class="gauge">{gauge_html}</div>
    <div class="legend">
      {''.join(f'<div class="legend-item"><div class="legend-dot" style="background:{_severity_color(s)}"></div>{s.capitalize()} ({summary["counts"].get(s,0)})</div>' for s in ["critical","high","medium","low","info"])}
    </div>
  </div>

  <!-- ── findings table ── -->
  <div class="section">
    <h2>Findings ({len(findings)})</h2>
    <div class="tbl-wrap">
      <table>
        <thead>
          <tr>
            <th>#</th><th>Severity</th><th>Title</th><th>Target</th>
            <th>Source</th><th>Type</th><th>Conf.</th><th>Score</th>
          </tr>
        </thead>
        <tbody>{rows_html}</tbody>
      </table>
    </div>
  </div>

  <!-- ── attack surface ── -->
  <div class="section">
    <h2>Attack Surface</h2>
    <div class="surface-grid">
      <div class="surface-box">
        <h3>Subdomains ({len(context.subdomains)})</h3>
        <ul>{subdomains_html}</ul>
      </div>
      <div class="surface-box">
        <h3>Services ({len(context.services)})</h3>
        <ul>{services_html}</ul>
      </div>
      <div class="surface-box">
        <h3>Endpoints ({len(context.endpoints)})</h3>
        <ul>{endpoints_html}</ul>
      </div>
    </div>
  </div>

  <footer>Generated by bug-bounty-ai &nbsp;·&nbsp; {generated}</footer>

</div>
</body>
</html>"""

    path.write_text(html, encoding="utf-8")
    logger.info(f"HTML report saved: {path}")
    return path


# ─────────────────────────────────────────────
# COMBINED EXPORT
# ─────────────────────────────────────────────

def export_all(context: Context) -> dict[str, Path]:
    """Export both JSON and HTML reports, return paths dict"""
    return {
        "json": export_json(context),
        "html": export_html(context),
    }
