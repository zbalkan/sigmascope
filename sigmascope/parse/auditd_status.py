from __future__ import annotations

from sigmascope.model import Diagnostic, Gate, Origin, ParseResult


def parse_auditd_status(source_id: str, data: str | bytes) -> ParseResult:
    text = (
        data.decode("utf-8", "surrogateescape")
        if isinstance(data, bytes)
        else data
    )
    for line_number, line in enumerate(text.splitlines(), start=1):
        key, separator, value = line.strip().partition(" ")
        if key != "enabled":
            continue
        origin = Origin(source_id, f"line {line_number}")
        if not separator:
            break
        try:
            enabled = int(value.split()[0])
        except (ValueError, IndexError):
            break
        return ParseResult(
            source_id,
            "effective",
            gates=(Gate("auditd.enabled", enabled, "effective", origin),),
        )

    return ParseResult(
        source_id,
        "unknown",
        diagnostics=(
            Diagnostic(
                "error",
                "auditctl -s did not contain a valid enabled state",
                Origin(source_id, "output"),
                text,
            ),
        ),
    )
