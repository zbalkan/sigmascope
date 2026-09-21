from __future__ import annotations

import importlib.util
from pathlib import Path

import pytest


SCRIPT = Path(__file__).parents[1] / "scripts" / "verify_release_tag.py"
SPEC = importlib.util.spec_from_file_location("verify_release_tag", SCRIPT)
assert SPEC is not None and SPEC.loader is not None
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)


def test_release_tag_must_match_package_version() -> None:
    assert MODULE.validate_tag("v0.1.0", "0.1.0") == "0.1.0"


@pytest.mark.parametrize("tag", ["0.1.0", "v0.1.1", ""])
def test_release_tag_rejects_invalid_or_mismatched_values(tag: str) -> None:
    with pytest.raises(ValueError):
        MODULE.validate_tag(tag, "0.1.0")


def test_release_script_reads_source_version() -> None:
    assert MODULE.read_source_version(Path(__file__).parents[1]) == "0.1.0"
