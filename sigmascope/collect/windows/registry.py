from __future__ import annotations

import sys

from sigmascope.model import Diagnostic, Gate, Origin, ParseResult


PROCESS_COMMAND_LINE = (
    r"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit",
    "ProcessCreationIncludeCmdLine_Enabled",
)

def collect_registry_gates() -> ParseResult:
    if sys.platform != "win32":
        return ParseResult("windows.registry", "unknown")

    import winreg

    path, value_name = PROCESS_COMMAND_LINE
    origin = Origin(
        "windows.registry",
        f"HKLM\\{path}\\{value_name}",
    )
    try:
        with winreg.OpenKey(
            winreg.HKEY_LOCAL_MACHINE,
            path,
            0,
            winreg.KEY_READ,
        ) as key:
            value, _ = winreg.QueryValueEx(key, value_name)
    except FileNotFoundError:
        value = 0
    except OSError as exc:
        return ParseResult(
            "windows.registry",
            "unknown",
            diagnostics=(Diagnostic("warn", str(exc), origin, ""),),
        )

    return ParseResult(
        "windows.registry",
        "effective",
        gates=(
            Gate(
                "windows.process_creation.include_command_line",
                bool(value),
                "effective",
                origin,
            ),
        ),
    )
