from __future__ import annotations

from sigmascope.model import Diagnostic, Gate, Origin, ParseResult


def parse_auditd_status(source_id: str, data: str | bytes) -> ParseResult:
    text = (
        data.decode("utf-8", "surrogateescape")
        if isinstance(data, bytes)
        else data
    )
    values: dict[str, tuple[int, Origin]] = {}
    diagnostics: list[Diagnostic] = []

    for line_number, line in enumerate(text.splitlines(), start=1):
        key, separator, raw = line.strip().partition(" ")
        if key not in {"enabled", "pid"}:
            continue
        origin = Origin(source_id, f"line {line_number}")
        if not separator:
            diagnostics.append(
                Diagnostic("warn", f"auditctl -s {key} has no value", origin, line)
            )
            continue
        try:
            values[key] = (int(raw.split()[0]), origin)
        except (ValueError, IndexError):
            diagnostics.append(
                Diagnostic(
                    "warn",
                    f"auditctl -s {key} is not numeric",
                    origin,
                    line,
                )
            )

    gates = tuple(
        Gate(f"auditd.{key}", value, origin)
        for key, (value, origin) in values.items()
    )
    missing = [key for key in ("enabled", "pid") if key not in values]
    if missing:
        diagnostics.append(
            Diagnostic(
                "error",
                "auditctl -s did not contain valid " + " and ".join(missing),
                Origin(source_id, "output"),
                text,
            )
        )

    return ParseResult(
        "unknown" if diagnostics else "effective",
        gates=gates,
        diagnostics=tuple(diagnostics),
    )
