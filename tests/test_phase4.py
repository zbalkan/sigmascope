from __future__ import annotations

from pathlib import Path

import sigmascope.api as api
import sigmascope.collect.windows.sysmon as sysmon_collect
from sigmascope.catalog import MAPPINGS_BY_OS
from sigmascope.collect.windows.channels import ChannelConfig
from sigmascope.evaluate.resolver import resolve_provider_disjunction
from sigmascope.evaluate.sysmon import evaluate_event_type
from sigmascope.evaluate.windows_gates import evaluate_windows_audit
from sigmascope.model import Gate, Origin, ParseResult, Verdict
from sigmascope.parse.sysmon_current import parse_sysmon_current


FIXTURES = Path(__file__).parent / "fixtures" / "sysmon"


def test_mapping_configuration_has_exactly_five_sourced_entries() -> None:
    mappings = tuple(
        entry
        for entries in MAPPINGS_BY_OS.values()
        for entry in entries
    )
    assert len(mappings) == 5
    assert all(entry["references"] for entry in mappings)


def test_sysmon_current_config_effective_network_gate_wins() -> None:
    parsed = parse_sysmon_current(
        "sysmon -c",
        (FIXTURES / "current_text_disabled.txt").read_text(encoding="utf-8"),
    )
    verdict, explanation = evaluate_event_type(parsed, "NetworkConnect")
    assert verdict is Verdict.NOT_COVERED
    assert "disabled" in explanation


def test_sysmon_current_config_preserves_filter_presence() -> None:
    parsed = parse_sysmon_current(
        "sysmon -c",
        (FIXTURES / "current_text_filtered.txt").read_text(encoding="utf-8"),
    )
    verdict, _ = evaluate_event_type(parsed, "NetworkConnect")
    assert verdict is Verdict.DEGRADED
    process, _ = evaluate_event_type(parsed, "ProcessCreate")
    assert process is Verdict.DEGRADED


def test_sysmon_current_config_parser_drift_is_indeterminate() -> None:
    parsed = parse_sysmon_current(
        "sysmon -c",
        (FIXTURES / "current_text_unknown_rule.txt").read_text(encoding="utf-8"),
    )
    assert parsed.determinacy == "unknown"
    verdict, _ = evaluate_event_type(parsed, "ProcessCreate")
    assert verdict is Verdict.INDETERMINATE


def test_windows_process_command_line_gate_degrades_security_provider() -> None:
    provider = {
        "subcategory_guid": "{0CCE922B-69AE-11D9-BED3-505054503030}",
        "required_states": ["success", "both"],
        "channel": "Security",
        "field_gate": {
            "key": "windows.process_creation.include_command_line",
            "explanation": "command line disabled",
        },
    }
    audit = ParseResult(
        "effective",
        gates=(
            Gate(
                "windows.audit.{0CCE922B-69AE-11D9-BED3-505054503030}",
                "success",
                Origin("audit", "guid"),
            ),
        ),
    )
    registry = ParseResult(
        "effective",
        gates=(
            Gate(
                "windows.process_creation.include_command_line",
                False,
                Origin("registry", "value"),
            ),
        ),
    )
    verdict, _, _ = evaluate_windows_audit(
        provider,
        audit,
        registry,
        ChannelConfig(True),
    )
    assert verdict is Verdict.DEGRADED


def test_file_system_audit_remains_indeterminate_without_sacl() -> None:
    provider = {
        "subcategory_guid": "{0CCE921D-69AE-11D9-BED3-505054503030}",
        "required_states": ["success", "both"],
        "channel": "Security",
        "necessary_but_insufficient": "SACL not evaluated",
    }
    audit = ParseResult(
        "effective",
        gates=(
            Gate(
                "windows.audit.{0CCE921D-69AE-11D9-BED3-505054503030}",
                "success",
                Origin("audit", "guid"),
            ),
        ),
    )
    verdict, explanation, _ = evaluate_windows_audit(
        provider,
        audit,
        ParseResult("effective"),
        ChannelConfig(True),
    )
    assert verdict is Verdict.INDETERMINATE
    assert "SACL" in explanation


def test_provider_disjunction_prefers_covered_then_degraded() -> None:
    requirement = {
        "logsource": {"category": "x", "product": "windows"},
        "references": ("https://example.invalid/source",)
    }
    providers = [
        {"source_id": "a", "verdict": "not_covered", "explanation": "off"},
        {"source_id": "b", "verdict": "covered", "explanation": "on"},
    ]
    assert resolve_provider_disjunction(requirement, providers)["verdict"] == "covered"


def test_provider_disjunction_prefers_indeterminate_over_degraded() -> None:
    requirement = {
        "logsource": {"category": "x", "product": "windows"},
        "references": ("https://example.invalid/source",)
    }
    providers = [
        {"source_id": "a", "verdict": "degraded", "explanation": "partial"},
        {"source_id": "b", "verdict": "indeterminate", "explanation": "unknown"},
    ]
    assert (
        resolve_provider_disjunction(requirement, providers)["verdict"]
        == "indeterminate"
    )


def test_windows_security_disabled_subcategory_is_not_covered() -> None:
    provider = {
        "subcategory_guid": "{0CCE922B-69AE-11D9-BED3-505054503030}",
        "required_states": ["success", "both"],
        "channel": "Security",
    }
    audit = ParseResult(
        "effective",
        gates=(
            Gate(
                "windows.audit.{0CCE922B-69AE-11D9-BED3-505054503030}",
                "none",
                Origin("audit", "guid"),
            ),
        ),
    )
    verdict, explanation, _ = evaluate_windows_audit(
        provider,
        audit,
        ParseResult("effective"),
        ChannelConfig(True),
    )
    assert verdict is Verdict.NOT_COVERED
    assert "present" in explanation
    assert "none" in explanation


def test_windows_security_unreadable_policy_is_indeterminate() -> None:
    provider = {
        "subcategory_guid": "{0CCE922B-69AE-11D9-BED3-505054503030}",
        "required_states": ["success", "both"],
        "channel": "Security",
    }
    verdict, explanation, _ = evaluate_windows_audit(
        provider,
        ParseResult("unknown"),
        ParseResult("effective"),
        ChannelConfig(True),
    )
    assert verdict is Verdict.INDETERMINATE
    assert "effective audit policy could not be determined" in explanation


def test_sysmon_absent_provider_reports_not_installed(monkeypatch) -> None:
    monkeypatch.setattr(
        sysmon_collect,
        "collect_sysmon",
        lambda: sysmon_collect.SysmonCollection(False, False, None, ()),
    )
    requirement = {
        "logsource": {"category": "process_creation", "product": "windows"},
        "providers": (
            {
                "kind": "sysmon",
                "source_id": "sysmon",
                "event_type": "ProcessCreate",
                "channel": "Microsoft-Windows-Sysmon/Operational",
            },
        ),
        "references": ("https://example.invalid/sysmon",),
    }
    findings, _, _ = api._run_windows([requirement])
    assert findings[0]["verdict"] == "not_covered"
    assert findings[0]["providers"][0]["explanation"] == "Sysmon is not installed."


def test_sysmon_stopped_provider_reports_installed_but_stopped(monkeypatch) -> None:
    monkeypatch.setattr(
        sysmon_collect,
        "collect_sysmon",
        lambda: sysmon_collect.SysmonCollection(True, False, None, ()),
    )
    requirement = {
        "logsource": {"category": "process_creation", "product": "windows"},
        "providers": (
            {
                "kind": "sysmon",
                "source_id": "sysmon",
                "event_type": "ProcessCreate",
                "channel": "Microsoft-Windows-Sysmon/Operational",
            },
        ),
        "references": ("https://example.invalid/sysmon",),
    }
    findings, _, _ = api._run_windows([requirement])
    assert findings[0]["verdict"] == "not_covered"
    assert "installed" in findings[0]["providers"][0]["explanation"]
    assert "not running" in findings[0]["providers"][0]["explanation"]


def test_windows_security_disabled_channel_is_not_covered() -> None:
    provider = {
        "subcategory_guid": "{0CCE922B-69AE-11D9-BED3-505054503030}",
        "required_states": ["success", "both"],
        "channel": "Security",
    }
    verdict, explanation, _ = evaluate_windows_audit(
        provider,
        ParseResult("effective"),
        ParseResult("effective"),
        ChannelConfig(False),
    )
    assert verdict is Verdict.NOT_COVERED
    assert "present" in explanation
    assert "disabled" in explanation
