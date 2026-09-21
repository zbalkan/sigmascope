from __future__ import annotations

import csv
from io import StringIO
import re

from sigmascope.model import Diagnostic, Gate, Origin, ParseResult


_GUID = re.compile(
    r"^\{[0-9A-Fa-f]{8}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-"
    r"[0-9A-Fa-f]{4}-[0-9A-Fa-f]{12}\}$"
)
_STATES = {
    "1": "success",
    "2": "failure",
    "3": "both",
    "": "unknown",
}
_SETTING_VALUES = frozenset(_STATES) | {"0"}


def _canonical_guid(value: str) -> str:
    return "{" + value.strip().strip("{}").upper() + "}"


def parse_auditpol_csv(source_id: str, data: str | bytes) -> ParseResult:
    """Parse auditpol report output without relying on localized headers."""
    text = data.decode("oem", "replace") if isinstance(data, bytes) else data
    rows = list(csv.reader(StringIO(text)))
    first_data_index: int | None = None
    guid_index: int | None = None
    setting_index: int | None = None

    for row_index, row in enumerate(rows):
        candidates = [
            index
            for index, value in enumerate(row)
            if _GUID.fullmatch(value.strip())
        ]
        if not candidates:
            continue
        guid_index = candidates[0]
        for index in range(len(row) - 1, -1, -1):
            if index != guid_index and row[index].strip() in _SETTING_VALUES:
                setting_index = index
                break
        if setting_index is not None:
            first_data_index = row_index
            break

    if first_data_index is None or guid_index is None or setting_index is None:
        return ParseResult(
            "unknown",
            diagnostics=(
                Diagnostic(
                    "error",
                    "could not locate GUID and setting-value columns in auditpol CSV",
                    Origin(source_id, "CSV"),
                    text,
                ),
            ),
        )

    gates: list[Gate] = []
    diagnostics: list[Diagnostic] = []
    for row_index, row in enumerate(rows[first_data_index:], start=first_data_index + 1):
        if max(guid_index, setting_index) >= len(row):
            diagnostics.append(
                Diagnostic(
                    "warn",
                    "short auditpol CSV row",
                    Origin(source_id, f"row {row_index}"),
                    ",".join(row),
                )
            )
            continue
        guid_text = row[guid_index].strip()
        if not _GUID.fullmatch(guid_text):
            continue
        raw_state = row[setting_index].strip()
        state = _STATES.get(raw_state)
        if raw_state == "0":
            diagnostics.append(
                Diagnostic(
                    "warn",
                    "auditpol setting value 0 is ambiguous between "
                    "no auditing and not specified",
                    Origin(source_id, f"row {row_index}"),
                    ",".join(row),
                )
            )
            state = "unknown"
        elif state is None:
            diagnostics.append(
                Diagnostic(
                    "warn",
                    f"unknown auditpol setting value {raw_state!r}",
                    Origin(source_id, f"row {row_index}"),
                    ",".join(row),
                )
            )
            state = "unknown"
        gates.append(
            Gate(
                f"windows.audit.{_canonical_guid(guid_text)}",
                state,
                Origin(source_id, f"row {row_index}"),
            )
        )

    return ParseResult(
        "unknown" if diagnostics else "effective",
        gates=tuple(gates),
        diagnostics=tuple(diagnostics),
    )
