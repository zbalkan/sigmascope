from __future__ import annotations

import os
import subprocess
import sys


def test_import_and_mapping_access_make_no_network_or_write_calls() -> None:
    script = r"""
import builtins
import socket

original_open = builtins.open

def guarded_open(file, mode="r", *args, **kwargs):
    if any(flag in mode for flag in ("w", "a", "x", "+")):
        raise RuntimeError(f"write attempted during import/mapping access: {file}")
    return original_open(file, mode, *args, **kwargs)

def blocked(*args, **kwargs):
    raise RuntimeError("network attempted during import/mapping access")

builtins.open = guarded_open
socket.create_connection = blocked
socket.socket.connect = blocked
socket.socket.connect_ex = blocked

import sigmascope
from sigmascope.catalog import CATALOG_VERSION, MAPPINGS_BY_OS
assert CATALOG_VERSION == "0.1.0"
assert MAPPINGS_BY_OS
"""
    env = dict(os.environ)
    env["PYTHONDONTWRITEBYTECODE"] = "1"
    subprocess.run(
        [sys.executable, "-B", "-c", script],
        env=env,
        check=True,
    )
