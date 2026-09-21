from __future__ import annotations

from typing import Any

from sigmascope.model import Verdict


_PROVIDER_ORDER = {
    Verdict.COVERED.value: 3,
    Verdict.INDETERMINATE.value: 2,
    Verdict.DEGRADED.value: 1,
    Verdict.NOT_COVERED.value: 0,
}


def resolve_provider_disjunction(
    requirement: dict[str, Any],
    providers: list[dict[str, Any]],
) -> dict[str, Any]:
    if not providers:
        verdict = Verdict.INDETERMINATE
        explanation = "No provider evaluation was available."
    else:
        best = max(
            providers,
            key=lambda item: _PROVIDER_ORDER.get(str(item.get("verdict")), -1),
        )
        verdict = Verdict(str(best["verdict"]))
        explanation = (
            str(best["explanation"])
            if verdict is Verdict.COVERED
            else "; ".join(
                f"{item.get('source_id', 'provider')}: {item.get('explanation', '')}"
                for item in providers
            )
        )

    return {
        "logsource": dict(requirement["logsource"]),
        "verdict": verdict.value,
        "satisfied": verdict.satisfied,
        "explanation": explanation,
        "providers": providers,
        "references": [str(requirement["reference"])],
    }
