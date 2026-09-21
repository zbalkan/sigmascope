from __future__ import annotations

import re

from sigmascope.model import (
    Diagnostic,
    Effect,
    EventTypeSelector,
    Gate,
    Origin,
    ParseResult,
    Predicate,
    Rule,
)


_SUMMARY = re.compile(r"^\s*-\s*(?P<key>[^:]+):\s*(?P<value>.*)$")
_RULE_HEADER = re.compile(
    r"^\s*-\s*(?P<event>[A-Za-z][A-Za-z0-9]+)\s+"
    r"onmatch:\s*(?P<effect>include|exclude)\s+"
    r"combine rules using ['\"](?:And|Or)['\"]",
    re.IGNORECASE,
)
_RULE_VERSION = re.compile(
    r"^\s*Rule configuration \(version [^)]+\):\s*$",
    re.IGNORECASE,
)
_FILTER = re.compile(
    r"^\s+(?P<field>[^:]+?)\s+filter:\s*.+?\s+"
    r"value:\s*['\"]?(?P<value>.*?)['\"]?\s*$",
    re.IGNORECASE,
)


def parse_sysmon_current(source_id: str, data: str | bytes) -> ParseResult:
    """Parse the read-only text emitted by sysmon -c."""
    text = data.decode("oem", "replace") if isinstance(data, bytes) else data
    gates: list[Gate] = []
    rules: list[Rule] = []
    diagnostics: list[Diagnostic] = []
    in_rules = False

    event: str | None = None
    effect: Effect | None = None
    origin: Origin | None = None
    raw: list[str] = []
    predicates: list[Predicate] = []
    complete = True

    def finish() -> None:
        nonlocal event, effect, origin, raw, predicates, complete
        if event is not None and effect is not None and origin is not None:
            rules.append(
                Rule(
                    effect=effect,
                    selector=EventTypeSelector(event),
                    predicates=tuple(predicates),
                    order=len(rules) + 1,
                    complete=complete,
                    origin=origin,
                    raw="\n".join(raw),
                )
            )
        event = None
        effect = None
        origin = None
        raw = []
        predicates = []
        complete = True

    for line_number, line in enumerate(text.splitlines(), start=1):
        line_origin = Origin(source_id, f"line {line_number}")

        if _RULE_VERSION.match(line):
            finish()
            in_rules = True
            continue

        if not in_rules:
            summary = _SUMMARY.match(line)
            if summary and summary.group("key").strip().lower() == "network connection":
                value = summary.group("value").strip().lower()
                if value in {"enabled", "disabled"}:
                    gates.append(
                        Gate(
                            "sysmon.NetworkConnect.enabled",
                            value == "enabled",
                            "effective",
                            line_origin,
                        )
                    )
                else:
                    diagnostics.append(
                        Diagnostic(
                            "warn",
                            "unrecognised Sysmon network-connection state",
                            line_origin,
                            line,
                        )
                    )
            if line.strip().lower() == "no rules installed":
                in_rules = True
            continue

        header = _RULE_HEADER.match(line)
        if header:
            finish()
            event = header.group("event")
            effect = Effect(header.group("effect").lower())
            origin = line_origin
            raw = [line]
            continue

        if not line.strip() or line.strip().lower() == "no rules installed":
            continue

        if event is None:
            diagnostics.append(
                Diagnostic(
                    "warn",
                    "unrecognised sysmon -c rule configuration line",
                    line_origin,
                    line,
                )
            )
            continue

        raw.append(line)
        match = _FILTER.match(line)
        if match:
            predicates.append(
                Predicate(
                    match.group("field").strip().lower().replace(" ", "_"),
                    "contains",
                    match.group("value").strip(),
                    line,
                )
            )
            continue

        if "compound rule" in line.lower():
            predicates.append(
                Predicate("compound_rule", "contains", line.strip(), line)
            )
            continue

        complete = False
        diagnostics.append(
            Diagnostic(
                "warn",
                "unrecognised sysmon -c rule syntax",
                line_origin,
                line,
            )
        )

    finish()
    return ParseResult(
        source_id,
        "unknown" if diagnostics else "effective",
        gates=tuple(gates),
        rules=tuple(rules),
        diagnostics=tuple(diagnostics),
    )
