from __future__ import annotations

from pathlib import Path

import pytest

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
    assert result.gates[0].key == "auditd.enabled"
    assert result.gates[0].value == 1


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
