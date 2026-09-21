from __future__ import annotations

import ast
import importlib.util
import json
from pathlib import Path
import subprocess
import sys
import sysconfig

import pytest

from sigmascope import run
from sigmascope.catalog import CATALOG_VERSION, MAPPINGS_BY_OS


PACKAGE = Path(__file__).parents[1] / "sigmascope"
STDLIB = set(getattr(sys, "stdlib_module_names", ()))


def _is_stdlib(name: str) -> bool:
    if name in STDLIB or name in {"__future__", "winreg"}:
        return True
    spec = importlib.util.find_spec(name)
    if spec is None or spec.origin in {None, "built-in", "frozen"}:
        return spec is not None
    origin = Path(spec.origin).resolve()
    purelib = Path(sysconfig.get_paths()["purelib"]).resolve()
    platlib = Path(sysconfig.get_paths()["platlib"]).resolve()
    if origin == purelib or purelib in origin.parents:
        return False
    if origin == platlib or platlib in origin.parents:
        return False
    stdlib = Path(sysconfig.get_paths()["stdlib"]).resolve()
    return origin == stdlib or stdlib in origin.parents


def test_no_third_party_runtime_imports() -> None:
    local = {path.name for path in PACKAGE.iterdir() if path.is_dir()} | {"sigmascope"}
    offenders: list[tuple[str, str]] = []
    for path in PACKAGE.rglob("*.py"):
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        for node in ast.walk(tree):
            names: list[str] = []
            if isinstance(node, ast.Import):
                names = [alias.name.split(".", 1)[0] for alias in node.names]
            elif isinstance(node, ast.ImportFrom) and node.module:
                names = [node.module.split(".", 1)[0]]
            for name in names:
                if name not in local and not _is_stdlib(name):
                    offenders.append((str(path.relative_to(PACKAGE.parent)), name))
    assert offenders == []


def test_no_module_scope_ctypes_windll() -> None:
    for path in PACKAGE.rglob("*.py"):
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        # Function and class bodies are intentionally excluded: guarded lazy native
        # loading is allowed; only import-time DLL loading is forbidden.
        module_executable = [
            node
            for node in tree.body
            if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef))
        ]
        assert "windll" not in ast.dump(ast.Module(body=module_executable, type_ignores=[])).lower()


def test_demo_report_shape() -> None:
    report = run(demo=True)
    assert report["schema_version"] == "0.1"
    assert report["layer"] == "generation"
    assert report["findings"][0]["verdict"] == "degraded"
    assert report["findings"][0]["satisfied"] is False


def test_demo_report_validates_against_schema() -> None:
    jsonschema = pytest.importorskip("jsonschema")
    schema = json.loads((PACKAGE / "schema" / "report-0.1.json").read_text(encoding="utf-8"))
    jsonschema.Draft202012Validator(schema).validate(run(demo=True))


def test_embedded_mappings_are_versioned() -> None:
    assert CATALOG_VERSION == "0.1.0"
    assert sum(len(entries) for entries in MAPPINGS_BY_OS.values()) == 5


def test_cli_demo_json() -> None:
    proc = subprocess.run(
        [sys.executable, "-m", "sigmascope", "--demo", "--format", "json"],
        check=False, capture_output=True, text=True,
    )
    assert proc.returncode == 0
    assert json.loads(proc.stdout)["findings"][0]["verdict"] == "degraded"


def test_fail_on_uses_exit_code_three() -> None:
    proc = subprocess.run(
        [sys.executable, "-m", "sigmascope", "--demo", "--fail-on", "degraded"],
        check=False, capture_output=True, text=True,
    )
    assert proc.returncode == 3
