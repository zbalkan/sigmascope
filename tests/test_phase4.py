from __future__ import annotations

from pathlib import Path

from sigmascope import load_catalog
from sigmascope.collect.windows.channels import ChannelConfig
from sigmascope.evaluate.resolver import resolve_provider_disjunction
from sigmascope.evaluate.sysmon import evaluate_event_type
from sigmascope.evaluate.windows_gates import evaluate_windows_audit
from sigmascope.model import Gate, Origin, ParseResult, Verdict
from sigmascope.parse.sysmon_current import parse_sysmon_current


FIXTURES = Path(__file__).parent / "fixtures" / "sysmon"


def test_catalog_has_exactly_five_sourced_poc_entries() -> None:
    catalog = load_catalog()
    requirements = catalog["requirements"]
    assert len(requirements) == 5
    for entry in requirements:
        assert entry["reference"]
        assert entry["source"]


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
        "provider_guid": "{54849625-5478-4994-A5BA-3E3B0328C30D}",
        "field_gate": {
            "key": "windows.process_creation.include_command_line",
            "explanation": "command line disabled",
        },
    }
    audit = ParseResult(
        "audit",
        "effective",
        gates=(
            Gate(
                "windows.audit.{0CCE922B-69AE-11D9-BED3-505054503030}",
                "success",
                "effective",
                Origin("audit", "guid"),
            ),
        ),
    )
    registry = ParseResult(
        "registry",
        "effective",
        gates=(
            Gate(
                "windows.process_creation.include_command_line",
                False,
                "effective",
                Origin("registry", "value"),
            ),
        ),
    )
    verdict, _, _ = evaluate_windows_audit(
        provider,
        audit,
        registry,
        ChannelConfig(True),
        True,
    )
    assert verdict is Verdict.DEGRADED


def test_file_system_audit_remains_indeterminate_without_sacl() -> None:
    provider = {
        "subcategory_guid": "{0CCE921D-69AE-11D9-BED3-505054503030}",
        "required_states": ["success", "both"],
        "channel": "Security",
        "provider_guid": "{54849625-5478-4994-A5BA-3E3B0328C30D}",
        "necessary_but_insufficient": "SACL not evaluated",
    }
    audit = ParseResult(
        "audit",
        "effective",
        gates=(
            Gate(
                "windows.audit.{0CCE921D-69AE-11D9-BED3-505054503030}",
                "success",
                "effective",
                Origin("audit", "guid"),
            ),
        ),
    )
    verdict, explanation, _ = evaluate_windows_audit(
        provider,
        audit,
        ParseResult("registry", "effective"),
        ChannelConfig(True),
        True,
    )
    assert verdict is Verdict.INDETERMINATE
    assert "SACL" in explanation


def test_provider_disjunction_prefers_covered_then_degraded() -> None:
    requirement = {
        "logsource": {"category": "x", "product": "windows"},
        "reference": "https://example.invalid/source",
    }
    providers = [
        {"source_id": "a", "verdict": "not_covered", "explanation": "off"},
        {"source_id": "b", "verdict": "covered", "explanation": "on"},
    ]
    assert resolve_provider_disjunction(requirement, providers)["verdict"] == "covered"


def test_provider_disjunction_prefers_indeterminate_over_degraded() -> None:
    requirement = {
        "logsource": {"category": "x", "product": "windows"},
        "reference": "https://example.invalid/source",
    }
    providers = [
        {"source_id": "a", "verdict": "degraded", "explanation": "partial"},
        {"source_id": "b", "verdict": "indeterminate", "explanation": "unknown"},
    ]
    assert (
        resolve_provider_disjunction(requirement, providers)["verdict"]
        == "indeterminate"
    )
