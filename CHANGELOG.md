# Changelog

All notable changes to this project will be documented in this file.

The format is based on Keep a Changelog, and this project adheres to Semantic Versioning.

## [Unreleased]

### Added
- Python 3.9 through 3.14 support, with CI coverage across every supported minor version.
- Read-only Windows advanced-audit-policy, channel, registry, provider, and Sysmon collectors.
- Effective Sysmon current-configuration and auditd parsers with conservative diagnostics.
- Five-entry, source-pinned POC Sigma logsource mapping configuration compiled into the package.
- Provider-disjunction resolver and generation-layer JSON/table reports.
- Wheel and sdist artifact verification.
- Tag-gated TestPyPI-first trusted-publishing workflow with provenance attestations.
- Manual live-host validation procedure for acceptance criteria A10-A13 and A16.

### Security
- Zero third-party runtime dependencies.
- No runtime network access or host-state mutation.
- GitHub Actions are pinned to immutable commit SHAs.
