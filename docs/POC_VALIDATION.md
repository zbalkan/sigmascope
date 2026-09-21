# POC live-host validation

Automated CI covers parser, evaluator, packaging, wheel installation, Linux-safe
imports, schema validation, and artifact smoke tests. The following acceptance criteria
remain live-host checks because CI fixtures cannot establish the behavior of the local
Windows audit subsystem or a production-style auditd host.

## A10 — non-admin Windows

Run sigmascope from a standard non-elevated account. The command must exit 0 unless
--fail-on is specified. Privilege failures must appear as collection errors and the affected
providers must resolve to INDETERMINATE rather than NOT_COVERED.

## A11 — non-English Windows

Run the same build on a Windows host whose display language is not English. Confirm that
audit-policy results are still keyed by subcategory GUID and that auditpol fallback values
match an English host configured with the same policy.

## A12 — native versus auditpol parity

From an elevated shell run:

    python scripts/manual_windows_validation.py

A successful run compares only the mapped subcategories and exits 0. auditpol numeric
value 0 is reported as ambiguous and is not treated as a mismatch because the CLI cannot
distinguish "No Auditing" from "Not specified". Any other GUID/state mismatch exits 3 and
must be investigated before release.

## A13 — Sysmon-only process creation

On a test host, leave Audit Process Creation disabled and run Sysmon with ProcessCreate
enabled. sigmascope must return COVERED for process_creation/windows and name Sysmon as the
provider that satisfies the disjunction.

## A16 — supported host matrix

Run the wheel end to end on Windows Server 2019, Windows Server 2022, RHEL 9 with its supported Python 3.9 interpreter, and Ubuntu 24.04. Capture the JSON report and command
exit code for each host.

Do not modify host policy as part of sigmascope validation. Prepare disposable test hosts
separately when a positive or negative configuration is required.
