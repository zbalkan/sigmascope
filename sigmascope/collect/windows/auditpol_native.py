from __future__ import annotations

import ctypes
from ctypes import wintypes
from dataclasses import dataclass
import sys
import uuid

from sigmascope.model import CollectionError


class GUID(ctypes.Structure):
    _fields_ = [
        ("Data1", ctypes.c_uint32),
        ("Data2", ctypes.c_uint16),
        ("Data3", ctypes.c_uint16),
        ("Data4", ctypes.c_ubyte * 8),
    ]

    @classmethod
    def from_string(cls, value: str) -> "GUID":
        raw = uuid.UUID(value.strip("{}"))
        return cls.from_buffer_copy(raw.bytes_le)

    def as_string(self) -> str:
        raw = ctypes.string_at(ctypes.byref(self), ctypes.sizeof(self))
        return "{" + str(uuid.UUID(bytes_le=raw)).upper() + "}"


class AUDIT_POLICY_INFORMATION(ctypes.Structure):
    _fields_ = [
        ("AuditSubCategoryGuid", GUID),
        ("AuditingInformation", ctypes.c_uint32),
        ("AuditCategoryGuid", GUID),
    ]


class LUID(ctypes.Structure):
    _fields_ = [
        ("LowPart", wintypes.DWORD),
        ("HighPart", wintypes.LONG),
    ]


class LUID_AND_ATTRIBUTES(ctypes.Structure):
    _fields_ = [
        ("Luid", LUID),
        ("Attributes", wintypes.DWORD),
    ]


class TOKEN_PRIVILEGES(ctypes.Structure):
    _fields_ = [
        ("PrivilegeCount", wintypes.DWORD),
        ("Privileges", LUID_AND_ATTRIBUTES * 1),
    ]


TOKEN_QUERY = 0x0008
TOKEN_ADJUST_PRIVILEGES = 0x0020
SE_PRIVILEGE_ENABLED = 0x00000002
ERROR_ACCESS_DENIED = 5
ERROR_NOT_ALL_ASSIGNED = 1300
SE_SECURITY_NAME = "SeSecurityPrivilege"

_POLICY_STATES = {
    0: "unchanged",
    1: "success",
    2: "failure",
    3: "both",
    4: "none",
}


@dataclass(frozen=True)
class NativeAuditPolicy:
    states: dict[str, str]
    error: CollectionError | None = None


def policy_state(flags: int) -> str:
    return _POLICY_STATES.get(flags, f"unknown:{flags}")


def _libraries() -> tuple[ctypes.WinDLL, ctypes.WinDLL]:  # type: ignore[name-defined]
    if sys.platform != "win32":
        raise OSError("Windows audit policy APIs are only available on Windows")

    advapi32 = ctypes.WinDLL("advapi32", use_last_error=True)
    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)

    advapi32.AuditQuerySystemPolicy.argtypes = [
        ctypes.POINTER(GUID),
        wintypes.ULONG,
        ctypes.POINTER(ctypes.POINTER(AUDIT_POLICY_INFORMATION)),
    ]
    advapi32.AuditQuerySystemPolicy.restype = wintypes.BOOLEAN
    advapi32.AuditFree.argtypes = [ctypes.c_void_p]
    advapi32.AuditFree.restype = None

    advapi32.OpenProcessToken.argtypes = [
        wintypes.HANDLE,
        wintypes.DWORD,
        ctypes.POINTER(wintypes.HANDLE),
    ]
    advapi32.OpenProcessToken.restype = wintypes.BOOL
    advapi32.LookupPrivilegeValueW.argtypes = [
        wintypes.LPCWSTR,
        wintypes.LPCWSTR,
        ctypes.POINTER(LUID),
    ]
    advapi32.LookupPrivilegeValueW.restype = wintypes.BOOL
    advapi32.AdjustTokenPrivileges.argtypes = [
        wintypes.HANDLE,
        wintypes.BOOL,
        ctypes.POINTER(TOKEN_PRIVILEGES),
        wintypes.DWORD,
        ctypes.c_void_p,
        ctypes.c_void_p,
    ]
    advapi32.AdjustTokenPrivileges.restype = wintypes.BOOL

    kernel32.GetCurrentProcess.argtypes = []
    kernel32.GetCurrentProcess.restype = wintypes.HANDLE
    kernel32.CloseHandle.argtypes = [wintypes.HANDLE]
    kernel32.CloseHandle.restype = wintypes.BOOL
    return advapi32, kernel32


def _raise_last_error(operation: str) -> None:
    code = ctypes.get_last_error()
    raise OSError(code, f"{operation} failed", None, code)


def _enable_security_privilege(
    advapi32: ctypes.WinDLL,  # type: ignore[name-defined]
    kernel32: ctypes.WinDLL,  # type: ignore[name-defined]
) -> None:
    token = wintypes.HANDLE()
    if not advapi32.OpenProcessToken(
        kernel32.GetCurrentProcess(),
        TOKEN_QUERY | TOKEN_ADJUST_PRIVILEGES,
        ctypes.byref(token),
    ):
        _raise_last_error("OpenProcessToken")
    try:
        luid = LUID()
        if not advapi32.LookupPrivilegeValueW(
            None,
            SE_SECURITY_NAME,
            ctypes.byref(luid),
        ):
            _raise_last_error("LookupPrivilegeValueW")
        privileges = TOKEN_PRIVILEGES()
        privileges.PrivilegeCount = 1
        privileges.Privileges[0].Luid = luid
        privileges.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED
        ctypes.set_last_error(0)
        if not advapi32.AdjustTokenPrivileges(
            token,
            False,
            ctypes.byref(privileges),
            0,
            None,
            None,
        ):
            _raise_last_error("AdjustTokenPrivileges")
        if ctypes.get_last_error() == ERROR_NOT_ALL_ASSIGNED:
            raise PermissionError(
                ERROR_NOT_ALL_ASSIGNED,
                "process token does not hold SeSecurityPrivilege",
            )
    finally:
        kernel32.CloseHandle(token)


def _query_once(
    advapi32: ctypes.WinDLL,  # type: ignore[name-defined]
    guid_array: object,
    count: int,
) -> dict[str, str]:
    buffer = ctypes.POINTER(AUDIT_POLICY_INFORMATION)()
    if not advapi32.AuditQuerySystemPolicy(
        guid_array,
        count,
        ctypes.byref(buffer),
    ):
        _raise_last_error("AuditQuerySystemPolicy")
    try:
        return {
            buffer[index].AuditSubCategoryGuid.as_string(): policy_state(
                int(buffer[index].AuditingInformation)
            )
            for index in range(count)
        }
    finally:
        if buffer:
            advapi32.AuditFree(buffer)


def query_system_policy(subcategory_guids: tuple[str, ...]) -> dict[str, str]:
    if not subcategory_guids:
        return {}

    advapi32, kernel32 = _libraries()
    guid_array = (GUID * len(subcategory_guids))(
        *(GUID.from_string(value) for value in subcategory_guids)
    )

    try:
        return _query_once(advapi32, guid_array, len(subcategory_guids))
    except OSError as exc:
        code = getattr(exc, "winerror", None) or getattr(exc, "errno", None)
        if code != ERROR_ACCESS_DENIED:
            raise

    _enable_security_privilege(advapi32, kernel32)
    return _query_once(advapi32, guid_array, len(subcategory_guids))


def collect_native_policy(
    subcategory_guids: tuple[str, ...],
) -> NativeAuditPolicy:
    try:
        return NativeAuditPolicy(query_system_policy(subcategory_guids))
    except (OSError, PermissionError) as exc:
        return NativeAuditPolicy(
            {},
            CollectionError(
                "windows.audit_policy",
                str(exc),
                "AuditQuerySystemPolicy",
            ),
        )
