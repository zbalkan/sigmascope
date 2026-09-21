from __future__ import annotations

from typing import Any


CATALOG_VERSION = "0.1.0"

# POC mappings are deliberately compiled into the package. They are configuration,
# not runtime-discovered data: sigmascope never downloads or loads mapping files.
REQUIREMENTS: tuple[dict[str, Any], ...] = (
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
        "reference": (
            "https://github.com/SigmaHQ/sigma/blob/"
            "2e8fd89f82d9104c1b30321a307254ddeea17de2/"
            "documentation/logsource-guides/windows/category/process_creation.md"
        ),
        "source": (
            "SigmaHQ/sigma@2e8fd89f82d9104c1b30321a307254ddeea17de2; "
            "nasbench/Eventlog_Compendium@0157a6bef8764781830d64a8f5170eedb65dfe3c"
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
        "reference": (
            "https://github.com/nasbench/Eventlog_Compendium/blob/"
            "0157a6bef8764781830d64a8f5170eedb65dfe3c/"
            "data/audit_policy_category_to_event_mapping.json"
        ),
        "source": (
            "SigmaHQ/sigma@2e8fd89f82d9104c1b30321a307254ddeea17de2; "
            "nasbench/Eventlog_Compendium@0157a6bef8764781830d64a8f5170eedb65dfe3c; "
            "Microsoft Sysmon documentation"
        ),
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
        "reference": (
            "https://github.com/nasbench/Eventlog_Compendium/blob/"
            "0157a6bef8764781830d64a8f5170eedb65dfe3c/"
            "data/audit_policy_category_to_event_mapping.json"
        ),
        "source": (
            "SigmaHQ/sigma@2e8fd89f82d9104c1b30321a307254ddeea17de2; "
            "nasbench/Eventlog_Compendium@0157a6bef8764781830d64a8f5170eedb65dfe3c"
        ),
    },
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
        "reference": "https://man7.org/linux/man-pages/man8/auditctl.8.html",
        "source": "Linux audit-userspace auditctl(8); Sigma logsource model",
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
        "reference": "https://man7.org/linux/man-pages/man7/audit.rules.7.html",
        "source": "Linux audit-userspace audit.rules(7); Sigma logsource model",
    },
)


def load_catalog() -> dict[str, object]:
    return {
        "catalog_version": CATALOG_VERSION,
        "requirements": list(REQUIREMENTS),
    }
