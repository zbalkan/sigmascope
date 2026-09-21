from __future__ import annotations

from dataclasses import asdict
from datetime import datetime, timezone
import platform
import socket
from typing import Any

from sigmascope.catalog import CATALOG_VERSION, MAPPINGS_BY_OS
from sigmascope.evaluate.auditd import evaluate_file_watch, evaluate_process_creation
from sigmascope.evaluate.resolver import resolve_provider_disjunction
from sigmascope.model import CollectionError, Diagnostic, Gate, Origin, ParseResult, Verdict


def _host() -> dict[str, str]:
    return {
        "hostname": socket.gethostname(),
        "os": platform.system().lower(),
        "os_version": platform.release(),
        "arch": platform.machine(),
    }


def _evidence_from_rules(parsed: ParseResult) -> list[dict[str, str]]:
    return [
        {
            "resource": rule.origin.resource,
            "locator": rule.origin.locator,
            "raw": rule.raw,
        }
        for rule in parsed.rules
    ]


def _evidence_from_gates(gates: tuple[Gate, ...]) -> list[dict[str, str]]:
    return [
        {
            "resource": gate.origin.resource,
            "locator": gate.origin.locator,
            "raw": f"{gate.key}={gate.value}",
        }
        for gate in gates
    ]


def _provider_result(
    source_id: str,
    verdict: Verdict,
    explanation: str,
    evidence: list[dict[str, str]],
) -> dict[str, object]:
    return {
        "source_id": source_id,
        "verdict": verdict.value,
        "explanation": explanation,
        "evidence": evidence,
    }


def _demo_report() -> dict[str, object]:
    finding = {
        "logsource": {
            "category": "process_creation",
            "product": "linux",
            "service": "auditd",
        },
        "verdict": "degraded",
        "satisfied": False,
        "explanation": "Demo finding: generation coverage is intentionally partial.",
        "providers": [],
        "references": ["https://github.com/zbalkan/sigmascope"],
    }
    return {
        "schema_version": "0.1",
        "generated_utc": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
        "tool_version": __import__("sigmascope").__version__,
        "catalog_version": CATALOG_VERSION,
        "layer": "generation",
        "host": _host(),
        "findings": [finding],
        "diagnostics": [],
        "collection_errors": [],
    }


def _run_linux(
    requirements: list[dict[str, Any]],
    arch: str,
) -> tuple[list[dict[str, Any]], list[Diagnostic], list[CollectionError]]:
    from sigmascope.collect.linux.auditd import collect_auditd
    from sigmascope.parse.auditd_rules import parse_auditd_rules
    from sigmascope.parse.auditd_status import parse_auditd_status

    collection = collect_auditd()
    diagnostics: list[Diagnostic] = []
    errors = list(collection.errors)

    parsed = (
        parse_auditd_rules("auditctl -l", collection.effective_rules)
        if collection.effective_rules is not None
        else ParseResult("unknown")
    )

    status = (
        parse_auditd_status("auditctl -s", collection.status)
        if collection.status is not None
        else ParseResult("unknown")
    )
    diagnostics.extend(parsed.diagnostics)
    diagnostics.extend(status.diagnostics)

    enabled = next(
        (gate.value for gate in status.gates if gate.key == "auditd.enabled"),
        None,
    )
    pid = next(
        (gate.value for gate in status.gates if gate.key == "auditd.pid"),
        None,
    )
    findings: list[dict[str, Any]] = []
    for requirement in requirements:
        provider_outputs: list[dict[str, Any]] = []
        for provider in requirement["providers"]:
            if provider.get("kind") != "auditd":
                continue
            if not collection.installed:
                verdict, explanation = (
                    Verdict.NOT_COVERED,
                    "auditd is not installed (auditctl was not found).",
                )
            elif enabled == 0:
                verdict, explanation = (
                    Verdict.NOT_COVERED,
                    "auditd is installed, but the Linux audit subsystem is disabled.",
                )
            elif pid == 0:
                verdict, explanation = (
                    Verdict.NOT_COVERED,
                    "auditd is installed, but the auditd daemon is not running.",
                )
            elif status.determinacy == "unknown" or enabled is None or pid is None:
                verdict, explanation = (
                    Verdict.INDETERMINATE,
                    "auditd is installed, but its runtime state could not be determined.",
                )
            elif collection.effective_rules is None:
                verdict, explanation = (
                    Verdict.INDETERMINATE,
                    "auditd is installed and running, but its effective rules could not be read.",
                )
            elif provider.get("requirement") == "process_creation":
                verdict, explanation = evaluate_process_creation(parsed, machine_arch=arch)
            elif provider.get("requirement") == "file_watch":
                verdict, explanation = evaluate_file_watch(parsed)
            else:
                verdict, explanation = (
                    Verdict.INDETERMINATE,
                    "Unknown auditd catalogue requirement.",
                )
            provider_outputs.append(
                _provider_result(
                    str(provider["source_id"]),
                    verdict,
                    explanation,
                    _evidence_from_gates(status.gates) + _evidence_from_rules(parsed),
                )
            )
        findings.append(resolve_provider_disjunction(requirement, provider_outputs))
    return findings, diagnostics, errors


def _native_policy_result(
    requirements: list[dict[str, Any]],
) -> tuple[ParseResult, list[CollectionError]]:
    from sigmascope.collect.windows.auditpol_cli import collect_cli_policy
    from sigmascope.collect.windows.auditpol_native import collect_native_policy

    guids = tuple(
        sorted(
            {
                str(provider["subcategory_guid"])
                for requirement in requirements
                for provider in requirement["providers"]
                if provider.get("kind") == "windows_audit"
            }
        )
    )
    native = collect_native_policy(guids)
    if native.error is None:
        gates = tuple(
            Gate(
                f"windows.audit.{guid.upper()}",
                state,
                Origin("AuditQuerySystemPolicy", guid),
            )
            for guid, state in native.states.items()
        )
        return ParseResult("effective", gates=gates), []

    cli = collect_cli_policy()
    errors = [native.error]
    if cli.parsed is not None:
        return cli.parsed, errors
    if cli.error is not None:
        errors.append(cli.error)
    return ParseResult("unknown"), errors


def _run_windows(
    requirements: list[dict[str, Any]],
) -> tuple[list[dict[str, Any]], list[Diagnostic], list[CollectionError]]:
    from sigmascope.collect.windows.channels import get_channel_config
    from sigmascope.collect.windows.registry import collect_registry_gates
    from sigmascope.collect.windows.sysmon import collect_sysmon
    from sigmascope.evaluate.sysmon import evaluate_event_type
    from sigmascope.evaluate.windows_gates import evaluate_windows_audit
    from sigmascope.parse.sysmon_current import parse_sysmon_current

    audit_policy, audit_errors = _native_policy_result(requirements)
    registry = collect_registry_gates()
    sysmon = collect_sysmon()

    diagnostics: list[Diagnostic] = list(audit_policy.diagnostics)
    diagnostics.extend(registry.diagnostics)
    errors: list[CollectionError] = list(audit_errors)
    errors.extend(sysmon.errors)

    channel_names = {
        str(provider["channel"])
        for requirement in requirements
        for provider in requirement.get("providers", ())
        if provider.get("channel")
    }
    channels = {name: get_channel_config(name) for name in channel_names}
    for config in channels.values():
        if config.error is not None:
            errors.append(config.error)

    sysmon_parsed: ParseResult | None = None
    if sysmon.current_config is not None:
        sysmon_parsed = parse_sysmon_current("sysmon -c", sysmon.current_config)
        diagnostics.extend(sysmon_parsed.diagnostics)

    findings: list[dict[str, Any]] = []
    for requirement in requirements:
        provider_outputs: list[dict[str, Any]] = []
        for provider in requirement["providers"]:
            kind = provider.get("kind")
            if kind == "windows_audit":
                channel = channels[str(provider["channel"])]
                verdict, explanation, gates = evaluate_windows_audit(
                    provider,
                    audit_policy,
                    registry,
                    channel,
                )
                provider_outputs.append(
                    _provider_result(
                        str(provider["source_id"]),
                        verdict,
                        explanation,
                        _evidence_from_gates(gates),
                    )
                )
            elif kind == "sysmon":
                if sysmon.running is False:
                    verdict, explanation = (
                        Verdict.NOT_COVERED,
                        "The Sysmon service is not installed or is not running.",
                    )
                    evidence = []
                elif sysmon.running is not True or sysmon_parsed is None:
                    verdict, explanation = (
                        Verdict.INDETERMINATE,
                        "Sysmon is present but its effective configuration could not be collected.",
                    )
                    evidence = []
                else:
                    channel = channels[str(provider["channel"])]
                    if channel.error or channel.enabled is None:
                        verdict, explanation = (
                            Verdict.INDETERMINATE,
                            "The Sysmon Operational channel state could not be determined.",
                        )
                    elif channel.enabled is False:
                        verdict, explanation = (
                            Verdict.NOT_COVERED,
                            "The Sysmon Operational channel is disabled.",
                        )
                    else:
                        verdict, explanation = evaluate_event_type(
                            sysmon_parsed,
                            str(provider["event_type"]),
                        )
                    evidence = _evidence_from_rules(sysmon_parsed)
                    evidence.extend(_evidence_from_gates(sysmon_parsed.gates))
                provider_outputs.append(
                    _provider_result(
                        str(provider["source_id"]),
                        verdict,
                        explanation,
                        evidence,
                    )
                )
        findings.append(resolve_provider_disjunction(requirement, provider_outputs))
    return findings, diagnostics, errors


def run(*, demo: bool = False) -> dict[str, object]:
    if demo:
        return _demo_report()

    host = _host()
    product = host["os"]
    requirements = list(MAPPINGS_BY_OS.get(product, ()))

    if product == "linux":
        findings, diagnostics, errors = _run_linux(requirements, host["arch"])
    elif product == "windows":
        findings, diagnostics, errors = _run_windows(requirements)
    else:
        findings, diagnostics = [], []
        errors = [
            CollectionError(
                "host",
                f"unsupported operating system {product!r}",
                platform.platform(),
            )
        ]

    return {
        "schema_version": "0.1",
        "generated_utc": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
        "tool_version": __import__("sigmascope").__version__,
        "catalog_version": CATALOG_VERSION,
        "layer": "generation",
        "host": host,
        "findings": findings,
        "diagnostics": [asdict(value) for value in diagnostics],
        "collection_errors": [asdict(value) for value in errors],
    }
