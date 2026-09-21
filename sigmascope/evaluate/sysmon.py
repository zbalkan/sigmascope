from __future__ import annotations

from sigmascope.model import Effect, EventTypeSelector, ParseResult, Verdict


def _gate(parsed: ParseResult, key: str) -> object | None:
    return next((gate.value for gate in parsed.gates if gate.key == key), None)


def evaluate_event_type(parsed: ParseResult, event_type: str) -> tuple[Verdict, str]:
    """Evaluate whether a Sysmon event type is generated, conservatively."""
    summary_gate = {
        "NetworkConnect": "sysmon.NetworkConnect.enabled",
        "ImageLoad": "sysmon.ImageLoad.enabled",
        "ProcessAccess": "sysmon.ProcessAccess.enabled",
    }.get(event_type)
    if summary_gate:
        value = _gate(parsed, summary_gate)
        if value is False:
            return (
                Verdict.NOT_COVERED,
                f"Sysmon effective configuration reports {event_type} disabled.",
            )
        if value == "unknown":
            return (
                Verdict.INDETERMINATE,
                f"Sysmon effective {event_type} gate could not be determined.",
            )

    matching = [
        rule
        for rule in parsed.rules
        if isinstance(rule.selector, EventTypeSelector)
        and rule.selector.event_type == event_type
    ]
    if parsed.determinacy == "unknown":
        return (
            Verdict.INDETERMINATE,
            f"Sysmon {event_type} configuration is incomplete or could not be parsed safely.",
        )
    if not matching:
        return (
            Verdict.COVERED,
            f"Sysmon {event_type} is absent from EventFiltering; ASSUMED to be logged unfiltered (V1).",
        )

    includes = [rule for rule in matching if rule.effect is Effect.INCLUDE]
    excludes = [rule for rule in matching if rule.effect is Effect.EXCLUDE]

    if includes:
        if not any(rule.predicates for rule in includes):
            return (
                Verdict.NOT_COVERED,
                f"Sysmon {event_type} has only empty include blocks; ASSUMED to log no events (V2).",
            )
        if excludes and any(rule.predicates for rule in excludes):
            return (
                Verdict.DEGRADED,
                f"Sysmon {event_type} is restricted by include filters and exclude filters; "
                "documented Sysmon semantics give exclude matches precedence.",
            )
        return (
            Verdict.DEGRADED,
            f"Sysmon {event_type} is restricted by include filters, so only matching events are generated.",
        )

    if excludes and any(rule.predicates for rule in excludes):
        return (
            Verdict.DEGRADED,
            f"Sysmon {event_type} is restricted by exclude filters, so matching events are omitted.",
        )

    return (
        Verdict.COVERED,
        f"Sysmon {event_type} has only empty exclude blocks; ASSUMED to log all events (V2).",
    )
