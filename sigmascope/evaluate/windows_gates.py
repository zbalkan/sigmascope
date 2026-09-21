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

    if channel.enabled is False:
        return (
            Verdict.NOT_COVERED,
            f"Windows Security auditing is present, but channel {provider['channel']} is disabled.",
            (),
        )
    if channel.error is not None or channel.enabled is None:
        return (
            Verdict.INDETERMINATE,
            f"Windows Security auditing is present, but channel {provider['channel']} state could not be determined.",
            (),
        )

    audit_gate = _find_gate(audit_policy, key)
    if audit_gate is None:
        message = (
            "Windows Security auditing is present, but effective audit policy "
            "could not be determined."
            if audit_policy.determinacy == "unknown"
            else (
                "Windows Security auditing is present, but audit subcategory "
                f"{guid} was not found in the effective policy."
            )
        )
        return Verdict.INDETERMINATE, message, ()

    if audit_gate.value in {"unknown", "unchanged"}:
        return (
            Verdict.INDETERMINATE,
            "Windows Security auditing is present, but audit subcategory "
            f"{guid} has no determinate effective state.",
            (audit_gate,),
        )

    required = {str(value) for value in provider.get("required_states", ())}
    if str(audit_gate.value) not in required:
        return (
            Verdict.NOT_COVERED,
            "Windows Security auditing is present, but audit subcategory "
            f"{guid} is {audit_gate.value}; required state is "
            + " or ".join(sorted(required))
            + ".",
            (audit_gate,),
        )

    evidence: list[Gate] = [audit_gate]
    field_gate = provider.get("field_gate")
    if isinstance(field_gate, dict):
        field_key = str(field_gate["key"])
        gate = _find_gate(registry, field_key)
        if gate is None:
            return (
                Verdict.INDETERMINATE,
                "Windows Security auditing is enabled, but field gate "
                f"{field_key} could not be determined.",
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
        f"Windows Security auditing is enabled for subcategory {guid}.",
        tuple(evidence),
    )
