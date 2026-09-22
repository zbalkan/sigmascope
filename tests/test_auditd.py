from __future__ import annotations

from pathlib import Path
import subprocess

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


@pytest.mark.parametrize(
    "name",
    [
        "arm_b32_only.rules",
        "arm_b64_only.rules",
        "no_arch.rules",
        "suppressed_watch.rules",
        "scoped_suppressed_watch.rules",
        "reversed_action.rules",
        "dual_target.rules",
    ],
)
def test_option_splitter_round_trips_added_fixtures(name: str) -> None:
    for line in (
        FIXTURES / name
    ).read_text(encoding="utf-8").splitlines():
        assert "".join(split_options(line)) == line


@pytest.mark.parametrize(
    "name",
    ["arm_b32_only.rules", "arm_b64_only.rules"],
)
def test_explicit_arch_selectors_are_not_interpreted_off_x86(
    name: str,
) -> None:
    verdict, explanation = evaluate_process_creation(
        parse_fixture(name),
        machine_arch="aarch64",
    )
    assert verdict is Verdict.INDETERMINATE
    assert "aarch64" in explanation


def test_arch_free_rules_still_cover_non_x86_hosts() -> None:
    verdict, _ = evaluate_process_creation(
        parse_fixture("no_arch.rules"),
        machine_arch="aarch64",
    )
    assert verdict is Verdict.COVERED


def test_unconditional_never_task_suppresses_file_watch() -> None:
    verdict, explanation = evaluate_file_watch(
        parse_fixture("suppressed_watch.rules")
    )
    assert verdict is Verdict.NOT_COVERED
    assert "ASSUMED" in explanation


def test_scoped_never_task_is_reported_against_file_watch() -> None:
    verdict, explanation = evaluate_file_watch(
        parse_fixture("scoped_suppressed_watch.rules")
    )
    assert verdict is Verdict.DEGRADED
    assert "never,task" in explanation


def test_unconditional_never_task_names_the_assumption() -> None:
    _, explanation = evaluate_process_creation(
        parse_fixture("never_task_all.rules")
    )
    assert "ASSUMED" in explanation
    assert "(A1)" in explanation


def test_reversed_action_order_is_accepted() -> None:
    result = parse_fixture("reversed_action.rules")
    assert not result.diagnostics
    assert result.determinacy == "effective"
    assert evaluate_process_creation(result)[0] is Verdict.COVERED


def test_one_rule_with_two_target_fields_counts_distinct_targets() -> None:
    _, explanation = evaluate_file_watch(parse_fixture("dual_target.rules"))
    assert "2 target" in explanation


def test_dual_target_rule_does_not_double_count_identical_paths() -> None:
    result = parse_auditd_rules(
        "dup",
        "-a always,exit -F path=/etc/passwd -F perm=wa -k a\n"
        "-a always,exit -F path=/etc/passwd -F perm=wa -k b\n",
    )
    _, explanation = evaluate_file_watch(result)
    assert "1 target" in explanation


def test_auditctl_absent_from_path_is_found_in_sbin(monkeypatch) -> None:
    monkeypatch.setattr(auditd_collect.shutil, "which", lambda name: None)
    monkeypatch.setattr(
        auditd_collect.os.path,
        "exists",
        lambda path: path == "/usr/sbin/auditctl",
    )
    assert auditd_collect._locate_auditctl() == ("/usr/sbin/auditctl", True)


def test_unsearchable_sbin_makes_auditd_absence_indeterminate(
    monkeypatch,
) -> None:
    monkeypatch.setattr(auditd_collect.shutil, "which", lambda name: None)
    monkeypatch.setattr(auditd_collect.os.path, "exists", lambda path: False)
    monkeypatch.setattr(auditd_collect.os.path, "isdir", lambda path: True)
    monkeypatch.setattr(auditd_collect.os, "access", lambda path, mode: False)
    collection = auditd_collect.collect_auditd()
    assert collection.installed is None
    assert collection.errors

    monkeypatch.setattr(
        auditd_collect,
        "collect_auditd",
        lambda: collection,
    )
    findings, _, _ = api._run_linux(list(LINUX_MAPPINGS), "x86_64")
    assert all(item["verdict"] == "indeterminate" for item in findings)


def test_conclusive_absence_remains_not_covered(monkeypatch) -> None:
    monkeypatch.setattr(auditd_collect.shutil, "which", lambda name: None)
    monkeypatch.setattr(auditd_collect.os.path, "exists", lambda path: False)
    monkeypatch.setattr(auditd_collect.os.path, "isdir", lambda path: True)
    monkeypatch.setattr(auditd_collect.os, "access", lambda path, mode: True)
    collection = auditd_collect.collect_auditd()
    assert collection.installed is False
    assert not collection.errors


def test_auditctl_timeout_is_reported_as_collection_error(monkeypatch) -> None:
    def hang(*args, **kwargs):
        raise subprocess.TimeoutExpired(cmd="auditctl -l", timeout=15)

    monkeypatch.setattr(auditd_collect.subprocess, "run", hang)
    output, error = auditd_collect._auditctl("/usr/sbin/auditctl", "-l")
    assert output is None
    assert error is not None
    assert "auditctl" in error.resource
