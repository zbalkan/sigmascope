from __future__ import annotations

from typing import TextIO


def render_table(report: dict[str, object], stream: TextIO | None = None) -> str:
    findings = report.get("findings", [])
    rows = [("LOGSOURCE", "VERDICT", "EXPLANATION")]
    for item in findings if isinstance(findings, list) else []:
        if not isinstance(item, dict):
            continue
        logsource = item.get("logsource", {})
        if isinstance(logsource, dict):
            name = "/".join(
                str(logsource.get(k, ""))
                for k in ("category", "product", "service")
                if logsource.get(k)
            )
        else:
            name = str(logsource)
        rows.append((name, str(item.get("verdict", "")), str(item.get("explanation", ""))))
    widths = [max(len(row[i]) for row in rows) for i in range(3)]
    lines = []
    for index, row in enumerate(rows):
        lines.append("  ".join(row[i].ljust(widths[i]) for i in range(3)).rstrip())
        if index == 0:
            lines.append("  ".join("-" * width for width in widths))
    text = "\n".join(lines) + "\n"
    if stream is not None:
        stream.write(text)
    return text
