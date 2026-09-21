from __future__ import annotations

import ctypes
from pathlib import Path

import sigmascope.collect.windows.auditpol_native as auditpol_native
from sigmascope.collect.windows.auditpol_native import (
    AUDIT_POLICY_INFORMATION,
    GUID,
    policy_state,
)
from sigmascope.collect.windows.channels import EVT_CHANNEL_CONFIG_ENABLED
from sigmascope.collect.windows.registry import PROCESS_COMMAND_LINE
from sigmascope.parse.auditpol_csv import parse_auditpol_csv


FIXTURES = Path(__file__).parent / "fixtures" / "auditpol"


def test_native_policy_struct_layout_and_flag_distinction() -> None:
    assert [name for name, _ in AUDIT_POLICY_INFORMATION._fields_] == [
        "AuditSubCategoryGuid",
        "AuditingInformation",
        "AuditCategoryGuid",
    ]
    assert ctypes.sizeof(GUID) == 16
    assert policy_state(0) == "unchanged"
    assert policy_state(4) == "none"
    assert policy_state(3) == "both"


def test_guid_round_trip() -> None:
    value = "{0CCE922B-69AE-11D9-BED3-505054503030}"
    assert GUID.from_string(value).as_string() == value


def test_localized_auditpol_csv_uses_guid_and_numeric_value() -> None:
    result = parse_auditpol_csv(
        "auditpol /r",
        (FIXTURES / "localized.csv").read_text(encoding="utf-8"),
    )
    gates = {gate.key: gate for gate in result.gates}
    process = gates[
        "windows.audit.{0CCE922B-69AE-11D9-BED3-505054503030}"
    ]
    network = gates[
        "windows.audit.{0CCE9226-69AE-11D9-BED3-505054503030}"
    ]
    unknown = gates[
        "windows.audit.{11111111-2222-3333-4444-555555555555}"
    ]
    assert process.value == "success"
    assert network.value == "both"
    assert unknown.value == "unknown"
    assert result.determinacy == "unknown"


def test_auditpol_zero_setting_is_ambiguous() -> None:
    result = parse_auditpol_csv(
        "auditpol /r",
        (FIXTURES / "zero.csv").read_text(encoding="utf-8"),
    )
    assert result.determinacy == "unknown"
    assert result.gates[0].value == "unknown"
    assert "ambiguous" in result.diagnostics[0].message


def test_native_query_tries_delegated_access_before_privilege(
    monkeypatch,
) -> None:
    calls = []
    monkeypatch.setattr(
        auditpol_native,
        "_libraries",
        lambda: ("advapi", "kernel"),
    )
    monkeypatch.setattr(
        auditpol_native,
        "_query_once",
        lambda advapi, array, count: calls.append("query")
        or {"{0CCE922B-69AE-11D9-BED3-505054503030}": "success"},
    )
    monkeypatch.setattr(
        auditpol_native,
        "_enable_security_privilege",
        lambda advapi, kernel: calls.append("privilege"),
    )

    result = auditpol_native.query_system_policy(
        ("{0CCE922B-69AE-11D9-BED3-505054503030}",)
    )
    assert result
    assert calls == ["query"]


def test_native_query_retries_access_denied_with_privilege(
    monkeypatch,
) -> None:
    calls = []
    attempts = iter((False, True))

    def query_once(advapi, array, count):
        calls.append("query")
        if not next(attempts):
            raise OSError(auditpol_native.ERROR_ACCESS_DENIED, "denied")
        return {"{0CCE922B-69AE-11D9-BED3-505054503030}": "success"}

    monkeypatch.setattr(
        auditpol_native,
        "_libraries",
        lambda: ("advapi", "kernel"),
    )
    monkeypatch.setattr(
        auditpol_native,
        "_query_once",
        query_once,
    )
    monkeypatch.setattr(
        auditpol_native,
        "_enable_security_privilege",
        lambda advapi, kernel: calls.append("privilege"),
    )

    result = auditpol_native.query_system_policy(
        ("{0CCE922B-69AE-11D9-BED3-505054503030}",)
    )
    assert result
    assert calls == ["query", "privilege", "query"]


def test_registry_gate_is_limited_to_process_command_line() -> None:
    assert PROCESS_COMMAND_LINE[1] == "ProcessCreationIncludeCmdLine_Enabled"


def test_event_channel_enabled_property_id_is_frozen() -> None:
    assert EVT_CHANNEL_CONFIG_ENABLED == 0
