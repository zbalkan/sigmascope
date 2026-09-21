from __future__ import annotations

from pathlib import Path

import pytest

import sigmascope.api as api
import sigmascope.collect.linux.auditd as auditd_collect
from sigmascope.catalog import LINUX_MAPPINGS
from sigmascope.evaluate.auditd import (
    evaluate_file_watch,
    evaluate_process_creation,
)
from sigmascope.model import Verdict
from sigmascope.parse.auditd_rules import parse_auditd_rules, split_options
from sigmascope.parse.auditd_status import parse_auditd_status


FIXTURES = Path(__file__).parent / "fixtures" / "auditd"


def parse_fixture(name: str):
    return parse_auditd_rules(
        name,
        (FIXTURES / name).read_bytes(),
    )


@pytest.mark.parametrize(
    "name",
    [
        "b64_only.rules",
        "both_arches.rules",
        "watch_space.rules",
        "dir_watch.rules",
        "operators.rules",
        "unset_auid.rules",
        "unknown.rules",
        "numeric.rules",
        "split_arch_syscalls.rules",
        "filtered_both_arches.rules",
        "early_never.rules",
        "never_task.rules",
        "never_task_all.rules",
    ],
)
def test_option_splitter_round_trips_every_fixture_line(
    name: str,
) -> None:
    for line in (
        FIXTURES / name
    ).read_text(encoding="utf-8").splitlines():
        assert "".join(split_options(line)) == line


def test_b64_only_is_degraded_and_names_missing_arch() -> None:
    verdict, explanation = evaluate_process_creation(
        parse_fixture("b64_only.rules")
    )
    assert verdict is Verdict.DEGRADED
    assert "b32" in explanation


def test_both_arches_are_covered() -> None:
    verdict, _ = evaluate_process_creation(
        parse_fixture("both_arches.rules")
    )
    assert verdict is Verdict.COVERED


def test_split_arch_syscalls_do_not_combine_into_false_coverage() -> None:
    verdict, explanation = evaluate_process_creation(
        parse_fixture("split_arch_syscalls.rules")
    )
    assert verdict is Verdict.DEGRADED
    assert "b32/execve" in explanation
    assert "b64/execveat" in explanation


def test_restrictive_filters_prevent_generic_coverage() -> None:
    verdict, explanation = evaluate_process_creation(
        parse_fixture("filtered_both_arches.rules")
    )
    assert verdict is Verdict.DEGRADED
    assert "restrictive" in explanation.lower()


def test_earlier_never_rule_prevents_covered_verdict() -> None:
    verdict, explanation = evaluate_process_creation(
        parse_fixture("early_never.rules")
    )
    assert verdict is Verdict.DEGRADED
    assert "before an always rule" in explanation


def test_watch_with_spaces_is_desugared() -> None:
    result = parse_fixture("watch_space.rules")
    rule = result.rules[0]
    values = {
        predicate.field: predicate.value
        for predicate in rule.predicates
    }
    assert values["path"] == "/opt/Company Product/config"
    assert values["perm"] == "wa"
    verdict, _ = evaluate_file_watch(result)
    assert verdict is Verdict.DEGRADED


def test_directory_rule_is_path_scoped_file_coverage() -> None:
    verdict, explanation = evaluate_file_watch(
        parse_fixture("dir_watch.rules")
    )
    assert verdict is Verdict.DEGRADED
    assert "1 target" in explanation


def test_filter_operator_set() -> None:
    result = parse_fixture("operators.rules")
    rule = result.rules[0]
    ops = {
        predicate.field: predicate.op
        for predicate in rule.predicates
    }
    assert ops["auid"] == "ne"
    assert ops["uid"] == "ge"
    assert ops["gid"] == "le"
    assert ops["exit"] == "bitest"
    assert ops["perm"] == "bitand"
    assert next(
        p.value
        for p in rule.predicates
        if p.field == "auid"
    ) == "unset"


def test_unset_auid_forms_normalise() -> None:
    result = parse_fixture("unset_auid.rules")
    assert next(
        p.value
        for p in result.rules[0].predicates
        if p.field == "auid"
    ) == "unset"


def test_unknown_option_is_diagnostic_and_indeterminate() -> None:
    result = parse_fixture("unknown.rules")
    assert result.diagnostics
    assert (
        evaluate_process_creation(result)[0]
        is Verdict.INDETERMINATE
    )


def test_numeric_syscalls_are_not_guessed() -> None:
    verdict, explanation = evaluate_process_creation(
        parse_fixture("numeric.rules")
    )
    assert verdict is Verdict.INDETERMINATE
    assert "numeric" in explanation


def test_status_parser() -> None:
    result = parse_auditd_status(
        "auditctl -s",
        (FIXTURES / "status.txt").read_text(),
    )
    gates = {gate.key: gate.value for gate in result.gates}
    assert gates["auditd.enabled"] == 1
    assert gates["auditd.pid"] == 827


def test_scoped_never_task_degrades_process_coverage() -> None:
    verdict, explanation = evaluate_process_creation(
        parse_fixture("never_task.rules")
    )
    assert verdict is Verdict.DEGRADED
    assert "scoped" in explanation.lower()


def test_unconditional_never_task_disables_process_coverage() -> None:
    verdict, explanation = evaluate_process_creation(
        parse_fixture("never_task_all.rules")
    )
    assert verdict is Verdict.NOT_COVERED
    assert "skip syscall-rule processing" in explanation


def test_auditd_missing_is_not_covered(monkeypatch) -> None:
    monkeypatch.setattr(
        auditd_collect,
        "collect_auditd",
        lambda: auditd_collect.AuditdCollection(False, None, None, ()),
    )
    findings, _, _ = api._run_linux(list(LINUX_MAPPINGS), "x86_64")
    assert all(item["verdict"] == "not_covered" for item in findings)
    assert all("not installed" in item["explanation"] for item in findings)


def test_auditd_disabled_is_not_covered(monkeypatch) -> None:
    monkeypatch.setattr(
        auditd_collect,
        "collect_auditd",
        lambda: auditd_collect.AuditdCollection(
            True,
            "",
            "enabled 0\npid 827\n",
            (),
        ),
    )
    findings, _, _ = api._run_linux(list(LINUX_MAPPINGS), "x86_64")
    assert all(item["verdict"] == "not_covered" for item in findings)
    assert all("installed" in item["explanation"] for item in findings)
    assert all("disabled" in item["explanation"] for item in findings)


def test_auditd_daemon_stopped_is_not_covered(monkeypatch) -> None:
    monkeypatch.setattr(
        auditd_collect,
        "collect_auditd",
        lambda: auditd_collect.AuditdCollection(
            True,
            "",
            "enabled 1\npid 0\n",
            (),
        ),
    )
    findings, _, _ = api._run_linux(list(LINUX_MAPPINGS), "x86_64")
    assert all(item["verdict"] == "not_covered" for item in findings)
    assert all("not running" in item["explanation"] for item in findings)


def test_auditd_inaccessible_remains_indeterminate(monkeypatch) -> None:
    monkeypatch.setattr(
        auditd_collect,
        "collect_auditd",
        lambda: auditd_collect.AuditdCollection(
            True,
            None,
            None,
            (),
        ),
    )
    findings, _, _ = api._run_linux(list(LINUX_MAPPINGS), "x86_64")
    assert all(item["verdict"] == "indeterminate" for item in findings)
    assert all("installed" in item["explanation"] for item in findings)
    assert all("could not be determined" in item["explanation"] for item in findings)
