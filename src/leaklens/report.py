"""Output formats: terminal text, JSON and SARIF."""
from __future__ import annotations

import json
import os
import sys
from collections import Counter
from typing import Dict, List, TextIO

from . import __version__
from .rules import RULES, SEVERITIES
from .scanner import Finding, redact

_COLORS = {"critical": "\033[1;31m", "high": "\033[31m", "medium": "\033[33m", "low": "\033[36m"}
_DIM, _BOLD, _GREEN, _RESET = "\033[2m", "\033[1m", "\033[32m", "\033[0m"
_SARIF_LEVEL = {"critical": "error", "high": "error", "medium": "warning", "low": "note"}
HOMEPAGE = "https://github.com/m4ks1em-maker/leaklens"


def use_color(stream: TextIO, disabled: bool) -> bool:
    if disabled or os.environ.get("NO_COLOR") or not hasattr(stream, "isatty") or not stream.isatty():
        return False
    if os.name == "nt":
        os.system("")  # switches the Windows console into ANSI mode
    return True


def sort_findings(findings: List[Finding]) -> List[Finding]:
    return sorted(findings, key=lambda f: (f.path, f.line, f.column))


def summary_line(findings: List[Finding]) -> str:
    counts = Counter(f.severity for f in findings)
    parts = [f"{counts[s]} {s}" for s in reversed(SEVERITIES) if counts[s]]
    noun = "secret" if len(findings) == 1 else "secrets"
    return f"{len(findings)} potential {noun} found ({', '.join(parts)})"


def render_text(findings: List[Finding], files_scanned: int, seconds: float, mode: str,
                color: bool, show_secrets: bool) -> str:
    def paint(code: str, text: str) -> str:
        return f"{code}{text}{_RESET}" if color else text

    out = [paint(_BOLD, f"LeakLens {__version__}") +
           f" - {mode}: {files_scanned} files scanned in {seconds:.2f}s", ""]
    if not findings:
        out.append(paint(_GREEN, "[ok] No secrets found."))
        return "\n".join(out) + "\n"

    by_path: Dict[str, List[Finding]] = {}
    for finding in sort_findings(findings):
        by_path.setdefault(finding.path, []).append(finding)
    for path, items in by_path.items():
        out.append(paint(_BOLD, path))
        for f in items:
            value = f.secret if show_secrets else redact(f.secret)
            where = f"{f.line}:{f.column}".ljust(9)
            row = (f"  {where} {paint(_COLORS[f.severity], f.severity.upper().ljust(8))} "
                   f"{f.rule_id.ljust(26)} {value}")
            out.append(row)
            detail = f"            {f.description}  id:{f.fingerprint}"
            if f.commit:
                detail += f"  commit:{f.commit} by {f.author} on {(f.date or '')[:10]}"
            out.append(paint(_DIM, detail))
        out.append("")
    out.append(paint(_COLORS["critical"], "[!] " + summary_line(findings)))
    out.append("    Revoke and rotate every real secret: deleting the line does not remove it from git history.")
    out.append("    False positive? Add '# leaklens:ignore' to the line or the id to .leaklensignore.")
    return "\n".join(out) + "\n"


def render_json(findings: List[Finding], files_scanned: int, show_secrets: bool) -> str:
    payload = {
        "tool": "leaklens",
        "version": __version__,
        "files_scanned": files_scanned,
        "total": len(findings),
        "findings": [f.to_dict(show_secrets) for f in sort_findings(findings)],
    }
    return json.dumps(payload, indent=2, ensure_ascii=False) + "\n"


def render_sarif(findings: List[Finding]) -> str:
    """SARIF 2.1.0, the format GitHub code scanning understands."""
    results = []
    for f in sort_findings(findings):
        message = f"{f.description} ({redact(f.secret)})"
        if f.commit:
            message += f", introduced in commit {f.commit}"
        results.append({
            "ruleId": f.rule_id,
            "level": _SARIF_LEVEL[f.severity],
            "message": {"text": message},
            "locations": [{"physicalLocation": {
                "artifactLocation": {"uri": f.path.replace(os.sep, "/")},
                "region": {"startLine": f.line, "startColumn": f.column},
            }}],
            "partialFingerprints": {"leaklens/v1": f.fingerprint},
        })
    sarif = {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {"driver": {
                "name": "LeakLens",
                "version": __version__,
                "informationUri": HOMEPAGE,
                "rules": [{
                    "id": r.id,
                    "name": r.id,
                    "shortDescription": {"text": r.description},
                    "defaultConfiguration": {"level": _SARIF_LEVEL[r.severity]},
                    "properties": {"severity": r.severity},
                } for r in RULES],
            }},
            "results": results,
        }],
    }
    return json.dumps(sarif, indent=2, ensure_ascii=False) + "\n"


def write(text: str, output: str = "") -> None:
    if output:
        with open(output, "w", encoding="utf-8", newline="\n") as handle:
            handle.write(text)
        return
    try:
        sys.stdout.write(text)
    except UnicodeEncodeError:  # legacy Windows code pages
        encoding = sys.stdout.encoding or "ascii"
        sys.stdout.write(text.encode(encoding, "replace").decode(encoding))
