Changelog
0.3.0 - Beta
Date: 2026-06-09

file : issue : status

src/platform/mod.rs : unused-imports : patched
src/main.rs : ptr-arg,redundant-pattern-matching,iter-cloned-collect : patched
tests/integration_masquerade.rs : useless-format : patched
src/impersonation.rs : needless-borrow : patched
src/sandbox.rs : clippy-closures-and-matches : patched
src/monitor.rs : trim-split-whitespace,zombie-child-wait : patched


0.2.0 - Unreleased
Added hunt and quarantine CLI mode with JSON reporting.
Implemented Windows minidump scaffold (MiniDumpWriteDump wrapper under cfg).
Expanded impersonation confusable mappings and added build-time generator placeholder.
Extended packer detection heuristics (MPRESS, ASPACK, THEMIDA, etc.).
Added optional, feature-gated YARA CLI hook (detect local rules via yara binary).
Various test improvements and CI-friendly ILLUSION_TEST_MODE.
Many bug fixes and code cleanup.


0.1.0 - Initial
Core deterministic triage engine: sandbox, monitor, dumper, report schema, basic heuristics.