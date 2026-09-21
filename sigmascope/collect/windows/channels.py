from __future__ import annotations

import ctypes
from ctypes import wintypes
from dataclasses import dataclass
import sys

from sigmascope.collect.base import CollectionError


EVT_CHANNEL_CONFIG_ENABLED = 0


class _EVT_VARIANT_UNION(ctypes.Union):
    _fields_ = [
        ("BooleanVal", wintypes.BOOL),
        ("UInt64Val", ctypes.c_uint64),
        ("Ptr", ctypes.c_void_p),
    ]


class EVT_VARIANT(ctypes.Structure):
    _anonymous_ = ("value",)
    _fields_ = [
        ("value", _EVT_VARIANT_UNION),
        ("Count", wintypes.DWORD),
        ("Type", wintypes.DWORD),
    ]


@dataclass(frozen=True)
class ChannelConfig:
    enabled: bool | None
    error: CollectionError | None = None


def get_channel_config(channel: str) -> ChannelConfig:
    if sys.platform != "win32":
        return ChannelConfig(
            None,
            CollectionError(
                "windows.channel",
                "Windows Event Log APIs are unavailable on this platform",
                channel,
            ),
        )

    dll = ctypes.WinDLL("wevtapi", use_last_error=True)
    dll.EvtOpenChannelConfig.argtypes = [
        ctypes.c_void_p,
        wintypes.LPCWSTR,
        wintypes.DWORD,
    ]
    dll.EvtOpenChannelConfig.restype = ctypes.c_void_p
    dll.EvtGetChannelConfigProperty.argtypes = [
        ctypes.c_void_p,
        ctypes.c_int,
        wintypes.DWORD,
        wintypes.DWORD,
        ctypes.c_void_p,
        ctypes.POINTER(wintypes.DWORD),
    ]
    dll.EvtGetChannelConfigProperty.restype = wintypes.BOOL
    dll.EvtClose.argtypes = [ctypes.c_void_p]
    dll.EvtClose.restype = wintypes.BOOL

    handle = dll.EvtOpenChannelConfig(None, channel, 0)
    if not handle:
        code = ctypes.get_last_error()
        return ChannelConfig(
            None,
            CollectionError(
                "windows.channel",
                f"EvtOpenChannelConfig failed: WinError {code}",
                channel,
            ),
        )

    try:
        value = EVT_VARIANT()
        used = wintypes.DWORD()
        if not dll.EvtGetChannelConfigProperty(
            handle,
            EVT_CHANNEL_CONFIG_ENABLED,
            0,
            ctypes.sizeof(value),
            ctypes.byref(value),
            ctypes.byref(used),
        ):
            code = ctypes.get_last_error()
            return ChannelConfig(
                None,
                CollectionError(
                    "windows.channel",
                    f"EvtGetChannelConfigProperty failed: WinError {code}",
                    channel,
                ),
            )
        return ChannelConfig(bool(value.BooleanVal))
    finally:
        dll.EvtClose(handle)
