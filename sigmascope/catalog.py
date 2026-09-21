from __future__ import annotations


CATALOG_VERSION = "0.1.0"

_EVENTLOG_MAPPING = (
    "https://github.com/nasbench/Eventlog_Compendium/blob/"
    "0157a6bef8764781830d64a8f5170eedb65dfe3c/"
    "data/audit_policy_category_to_event_mapping.json"
)
_SYSMON_REFERENCE = "https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon"

WINDOWS_MAPPINGS = (
    {
        "logsource": {
            "category": "process_creation",
            "product": "windows",
        },
        "providers": (
            {
                "kind": "windows_audit",
                "source_id": "windows_security",
                "subcategory_guid": "{0CCE922B-69AE-11D9-BED3-505054503030}",
                "required_states": ("success", "both"),
                "channel": "Security",
                "field_gate": {
                    "key": "windows.process_creation.include_command_line",
                    "explanation": (
                        "Security 4688 is generated, but command-line inclusion "
                        "is disabled."
                    ),
                },
            },
            {
                "kind": "sysmon",
                "source_id": "sysmon",
                "event_type": "ProcessCreate",
                "channel": "Microsoft-Windows-Sysmon/Operational",
            },
        ),
        "references": (
            "https://github.com/SigmaHQ/sigma/blob/"
            "2e8fd89f82d9104c1b30321a307254ddeea17de2/"
            "documentation/logsource-guides/windows/category/process_creation.md",
            _EVENTLOG_MAPPING,
            _SYSMON_REFERENCE,
        ),
    },
    {
        "logsource": {
            "category": "network_connection",
            "product": "windows",
        },
        "providers": (
            {
                "kind": "windows_audit",
                "source_id": "windows_security",
                "subcategory_guid": "{0CCE9226-69AE-11D9-BED3-505054503030}",
                "required_states": ("success", "both"),
                "channel": "Security",
            },
            {
                "kind": "sysmon",
                "source_id": "sysmon",
                "event_type": "NetworkConnect",
                "channel": "Microsoft-Windows-Sysmon/Operational",
            },
        ),
        "references": (_EVENTLOG_MAPPING, _SYSMON_REFERENCE),
    },
    {
        "logsource": {
            "category": "file_event",
            "product": "windows",
        },
        "providers": (
            {
                "kind": "windows_audit",
                "source_id": "windows_security",
                "subcategory_guid": "{0CCE921D-69AE-11D9-BED3-505054503030}",
                "required_states": ("success", "both"),
                "channel": "Security",
                "necessary_but_insufficient": (
                    "Object Access File System auditing also requires an applicable "
                    "SACL on each target object. The POC does not evaluate SACLs."
                ),
            },
        ),
        "references": (_EVENTLOG_MAPPING,),
    },
)

LINUX_MAPPINGS = (
    {
        "logsource": {
            "category": "process_creation",
            "product": "linux",
            "service": "auditd",
        },
        "providers": (
            {
                "kind": "auditd",
                "source_id": "auditd",
                "requirement": "process_creation",
            },
        ),
        "references": ("https://man7.org/linux/man-pages/man8/auditctl.8.html",),
    },
    {
        "logsource": {
            "category": "file_event",
            "product": "linux",
            "service": "auditd",
        },
        "providers": (
            {
                "kind": "auditd",
                "source_id": "auditd",
                "requirement": "file_watch",
            },
        ),
        "references": ("https://man7.org/linux/man-pages/man7/audit.rules.7.html",),
    },
)

MAPPINGS_BY_OS = {
    "windows": WINDOWS_MAPPINGS,
    "linux": LINUX_MAPPINGS,
}
