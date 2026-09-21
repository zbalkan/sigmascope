# sigmascope

sigmascope is a read-only attestation tool for local telemetry-generation configuration.
It answers one deliberately narrow question: if a Sigma rule for a logsource were deployed,
would this host be configured to emit the events that logsource needs?

It does not attest collection, transport, parsing, indexing, or queryability. It does not
parse event records and never modifies host configuration. The 0.1 POC covers Windows
advanced audit policy and Sysmon plus Linux auditd generation configuration.

This project is independent of SigmaHQ and is not an official SigmaHQ project.

## Requirements

Python 3.9 through Python 3.14 are supported. This includes RHEL 9's default Python 3.9 interpreter.

There are no third-party runtime dependencies and no runtime network access.

## Usage

    sigmascope [--format json|table]
               [--fail-on none|degraded|not_covered|indeterminate]
               [--print-schema]
               [--print-catalog-version]
               [--demo]

A normal run inspects the current host. --demo exercises the report contract without making
host claims. Exit code 0 means the tool ran successfully, even when gaps were found. Exit
code 3 is used only when a requested --fail-on threshold is met.

The JSON report always sets layer to generation. A COVERED result therefore says nothing
about forwarding, collection, parsing, indexing, retention, or queryability.

## POC mappings

The five POC mappings are compiled into the package as Python configuration. sigmascope
does not load mapping files or fetch mappings at runtime. The mappings cover Windows
process creation, Windows network connection, Windows file events, Linux auditd process
creation, and Linux auditd file events. Windows process and network entries use provider disjunctions. Windows file-event
coverage stays INDETERMINATE when the File System audit subcategory is enabled because the
POC deliberately does not inspect target-object SACLs.

## Conservative semantics

Known source absence or disablement resolves to NOT_COVERED rather than INDETERMINATE.
For auditd this distinguishes not installed, kernel auditing disabled, daemon stopped,
and installed-but-unreadable state. For Sysmon it distinguishes not installed, service
stopped, service state inaccessible, running-but-unreadable configuration, and a disabled
Operational channel. Windows Security auditing distinguishes disabled channels or audit
subcategories from policy state that cannot be read.

Parser gaps, privilege failures, and other cases where source state cannot be inspected
resolve to INDETERMINATE. Linux coverage is based on effective auditctl -l output, not
declared rule files. Sysmon is evaluated from the read-only sysmon -c
current-configuration dump. The compiled Sysmon Rules registry blob is never parsed.

Sysmon assumptions V1-V2 remain explicit in fixtures and explanations until they are
verified on a live host. Mixed include/exclude precedence follows Microsoft documentation.
