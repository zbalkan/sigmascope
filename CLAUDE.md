# sigmascope implementation rules

- Write the fixture before the parser. A parser without a fixture that fails first is not accepted.
- One commit per phase gate, with the gate criteria and evidence in the commit message.
- Do not skip a gate to unblock a later phase. If a gate cannot be met, stop and report why.
- Do not add a runtime dependency. If something appears to need one, stop and report.
- Do not add a mapping without a source URL. Keep POC mappings in `sigmascope/catalog.py`; do not add runtime mapping files or network retrieval.
- Do not widen scope into log parsing, transport inspection, ETW sessions, eBPF, or runtime Sigma compilation.
- Do not resolve a semantic question by intuition. Encode it as an ASSUMED fixture, document the assumption, and require empirical verification.
- Prefer INDETERMINATE to a guess.
- Never modify host logging configuration.
- Never fetch or load mapping configuration at runtime.
