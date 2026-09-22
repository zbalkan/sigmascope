from __future__ import annotations

import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
from dataclasses import dataclass

from sigmascope.model import CollectionError


@dataclass(frozen=True)
class SysmonCollection:
    installed: bool | None
    running: bool | None
    current_config: bytes | None
    errors: tuple[CollectionError, ...] = ()


def _service_state(name: str) -> tuple[bool | None, bool, str | None]:
    if sys.platform != "win32":
        return None, False, "Windows service APIs are unavailable"
    import ctypes
    from ctypes import wintypes

    SC_MANAGER_CONNECT = 0x0001
    SERVICE_QUERY_STATUS = 0x0004
    SC_STATUS_PROCESS_INFO = 0
    SERVICE_RUNNING = 0x00000004
    ERROR_SERVICE_DOES_NOT_EXIST = 1060

    class SERVICE_STATUS_PROCESS(ctypes.Structure):
        _fields_ = [
            ("dwServiceType", wintypes.DWORD),
            ("dwCurrentState", wintypes.DWORD),
            ("dwControlsAccepted", wintypes.DWORD),
            ("dwWin32ExitCode", wintypes.DWORD),
            ("dwServiceSpecificExitCode", wintypes.DWORD),
            ("dwCheckPoint", wintypes.DWORD),
            ("dwWaitHint", wintypes.DWORD),
            ("dwProcessId", wintypes.DWORD),
            ("dwServiceFlags", wintypes.DWORD),
        ]

    advapi32 = ctypes.WinDLL("advapi32", use_last_error=True)
    advapi32.OpenSCManagerW.argtypes = [
        wintypes.LPCWSTR,
        wintypes.LPCWSTR,
        wintypes.DWORD,
    ]
    advapi32.OpenSCManagerW.restype = wintypes.HANDLE
    advapi32.OpenServiceW.argtypes = [
        wintypes.HANDLE,
        wintypes.LPCWSTR,
        wintypes.DWORD,
    ]
    advapi32.OpenServiceW.restype = wintypes.HANDLE
    advapi32.QueryServiceStatusEx.argtypes = [
        wintypes.HANDLE,
        wintypes.INT,
        ctypes.POINTER(ctypes.c_ubyte),
        wintypes.DWORD,
        ctypes.POINTER(wintypes.DWORD),
    ]
    advapi32.QueryServiceStatusEx.restype = wintypes.BOOL
    advapi32.CloseServiceHandle.argtypes = [wintypes.HANDLE]
    advapi32.CloseServiceHandle.restype = wintypes.BOOL

    scm = advapi32.OpenSCManagerW(None, None, SC_MANAGER_CONNECT)
    if not scm:
        return None, False, f"OpenSCManagerW failed: WinError {ctypes.get_last_error()}"
    try:
        service = advapi32.OpenServiceW(scm, name, SERVICE_QUERY_STATUS)
        if not service:
            code = ctypes.get_last_error()
            if code == ERROR_SERVICE_DOES_NOT_EXIST:
                return False, False, None
            return None, False, f"OpenServiceW failed: WinError {code}"
        try:
            status = SERVICE_STATUS_PROCESS()
            needed = wintypes.DWORD()
            ok = advapi32.QueryServiceStatusEx(
                service,
                SC_STATUS_PROCESS_INFO,
                ctypes.cast(ctypes.byref(status), ctypes.POINTER(ctypes.c_ubyte)),
                ctypes.sizeof(status),
                ctypes.byref(needed),
            )
            if not ok:
                return None, True, (
                    f"QueryServiceStatusEx failed: WinError {ctypes.get_last_error()}"
                )
            return status.dwCurrentState == SERVICE_RUNNING, True, None
        finally:
            advapi32.CloseServiceHandle(service)
    finally:
        advapi32.CloseServiceHandle(scm)


def _service_key(name: str) -> str:
    return rf"SYSTEM\CurrentControlSet\Services\{name}"


def _service_image_path(name: str) -> str | None:
    if sys.platform != "win32":
        return None
    import winreg

    path = _service_key(name)
    try:
        with winreg.OpenKey(
            winreg.HKEY_LOCAL_MACHINE,
            path,
            0,
            winreg.KEY_READ,
        ) as key:
            raw, _ = winreg.QueryValueEx(key, "ImagePath")
    except OSError:
        return None
    if not isinstance(raw, str):
        return None
    value = os.path.expandvars(raw.strip())
    match = re.match(r'^"([^"]+)"', value)
    executable = match.group(1) if match else value.split(None, 1)[0]
    system_root_prefix = chr(92) + "systemroot" + chr(92)
    if executable.lower().startswith(system_root_prefix):
        root = os.environ.get("SystemRoot", "C:" + chr(92) + "Windows")
        executable = str(Path(root) / executable[len(system_root_prefix):])
    return executable


def collect_sysmon() -> SysmonCollection:
    if sys.platform != "win32":
        return SysmonCollection(
            None,
            None,
            None,
            (
                CollectionError(
                    "sysmon",
                    "Sysmon collection is only available on Windows",
                    "Windows SCM",
                ),
            ),
        )

    errors: list[CollectionError] = []
    service_name: str | None = None
    running: bool | None = None
    for candidate in ("Sysmon64", "Sysmon"):
        state, exists, error = _service_state(candidate)
        if error:
            errors.append(CollectionError("sysmon", error, candidate))
        if exists:
            service_name = candidate
            running = state
            break

    if service_name is None:
        installed = None if errors else False
        return SysmonCollection(installed, False if installed is False else None, None, tuple(errors))
    if running is not True:
        return SysmonCollection(True, running, None, tuple(errors))

    candidates: list[str] = []
    image = _service_image_path(service_name)
    if image:
        candidates.append(image)
    for name in ("Sysmon64.exe", "Sysmon.exe", "sysmon.exe"):
        found = shutil.which(name)
        if found and found not in candidates:
            candidates.append(found)

    executable = next(
        (candidate for candidate in candidates if Path(candidate).is_file()),
        None,
    )
    if executable is None:
        errors.append(
            CollectionError(
                "sysmon",
                "Sysmon service is running but its executable could not be located",
                service_name,
            )
        )
        return SysmonCollection(True, True, None, tuple(errors))

    try:
        proc = subprocess.run(
            (executable, "-c"),
            check=False,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=15,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        errors.append(CollectionError("sysmon", str(exc), f"{executable} -c"))
        return SysmonCollection(True, True, None, tuple(errors))

    if proc.returncode != 0:
        message = proc.stderr.decode("oem", "replace").strip()
        errors.append(
            CollectionError(
                "sysmon",
                message or f"sysmon -c exited {proc.returncode}",
                f"{executable} -c",
            )
        )
        return SysmonCollection(True, True, None, tuple(errors))

    output = proc.stdout or proc.stderr
    return SysmonCollection(True, True, output, tuple(errors))
