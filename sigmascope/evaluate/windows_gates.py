from __future__ import annotations

from typing import Any

from sigmascope.collect.windows.channels import ChannelConfig
from sigmascope.model import Gate, ParseResult, Verdict


def _find_gate(parsed: ParseResult, key: str) -> Gate | None:
    return next((gate for gate in parsed.gates if gate.key == key), None)


def evaluate_windows_audit(
    provider: dict[str, Any],
    audit_policy: ParseResult,
    registry: ParseResult,
    channel: ChannelConfig,
) -> tuple[Verdict, str, tuple[Gate, ...]]:
    guid = str(provider["subcategory_guid"]).upper()
    key = f"windows.audit.{guid}"

    if channel.error is not None or channel.enabled is None:
        return (
            Verdict.INDETERMINATE,
            f"Channel {provider['channel']} configuration could not be determined.",
            (),
        )
    if channel.enabled is False:
        return (
            Verdict.NOT_COVERED,
            f"Channel {provider['channel']} is disabled.",
            (),
        )

    audit_gate = _find_gate(audit_policy, key)
    if audit_gate is None:
        return (
            Verdict.INDETERMINATE,
            f"Audit subcategory {guid} is absent from the collected effective policy.",
            (),
        )
    if audit_gate.determinacy == "unknown" or audit_gate.value in {"unknown", "unchanged"}:
        return (
            Verdict.INDETERMINATE,
            f"Audit subcategory {guid} has no determinate effective state.",
            (audit_gate,),
        )

    required = {str(value) for value in provider.get("required_states", ())}
    if str(audit_gate.value) not in required:
        return (
            Verdict.NOT_COVERED,
            f"Audit subcategory {guid} is {audit_gate.value}; required state is "
            + " or ".join(sorted(required))
            + ".",
            (audit_gate,),
        )

    evidence: list[Gate] = [audit_gate]
    field_gate = provider.get("field_gate")
    if isinstance(field_gate, dict):
        field_key = str(field_gate["key"])
        gate = _find_gate(registry, field_key)
        if gate is None or gate.determinacy == "unknown":
            return (
                Verdict.INDETERMINATE,
                f"Field gate {field_key} could not be determined.",
                tuple(evidence),
            )
        evidence.append(gate)
        if gate.value is not True:
            return (
                Verdict.DEGRADED,
                str(field_gate["explanation"]),
                tuple(evidence),
            )

    insufficient = provider.get("necessary_but_insufficient")
    if insufficient:
        return Verdict.INDETERMINATE, str(insufficient), tuple(evidence)

    return (
        Verdict.COVERED,
        f"Audit subcategory {guid} is enabled and its channel gate is enabled.",
        tuple(evidence),
    )
