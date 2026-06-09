Changelog
0.4.0 - Beta
Added

dumper.rs: Windows in-memory SHA‑256 hashing for an executable image (compute_memory_sha256_for_exe) using Toolhelp + ReadProcessMemory.
sandbox.rs: Job-object based Windows spawner to contain/terminate spawned processes (WindowsSpawner) and tighter cross-platform spawn lifecycle handling.
sandbox.rs: PCAP capture autodetection and per-flow PCAP extraction with fallbacks (tcpdump → tshark/dumpcap → windump).
pe.rs: New PE parsing helpers (PE analysis utilities).
yara_wrapper.rs: YARA wrapper scaffolding for optional YARA rule scanning integration.
scripts/package_release.sh: Packaging script updated to build and produce cross-platform dist artifacts (Linux binary, Windows .exe, tar/zip).
Changed

Dumper logic: Unified dump/hash flow across platforms and improved fallback/error handling when producing core/memory dumps.
Sandbox & monitor: Aligned sandbox capture/report pipeline between Linux and Windows (per-flow reporting and artifact generation).
windows.rs: Improved Windows helpers (wide-string handling and Win32 FFI helpers).
Build / features: Enabled/adjusted windows-backend feature and build config to support x86_64-pc-windows-gnu cross-builds.
Codebase: Broad Clippy and formatting fixes across modules (lib.rs, main.rs, monitor.rs, report.rs, etc.).
Fixed

Cross-build/linker/tooling issues preventing Windows GNU builds (adjusted build-related code/flags).
Multiple Clippy-detected issues and runtime edge cases in hashing/dump routines.
Removed

Outdated integration tests that conflicted with refactors (tests/integration_dynamic.rs, tests/integration_masquerade.rs).

-------------------------------------------------------------------

0.3.0 - Beta
Date: 2026-06-09

file : issue : status

src/platform/mod.rs : unused-imports : patched
src/main.rs : ptr-arg,redundant-pattern-matching,iter-cloned-collect : patched
tests/integration_masquerade.rs : useless-format : patched
src/impersonation.rs : needless-borrow : patched
src/sandbox.rs : clippy-closures-and-matches : patched
src/monitor.rs : trim-split-whitespace,zombie-child-wait : patched

-------------------------------------------------------------------

0.2.0 - Unreleased
Added hunt and quarantine CLI mode with JSON reporting.
Implemented Windows minidump scaffold (MiniDumpWriteDump wrapper under cfg).
Expanded impersonation confusable mappings and added build-time generator placeholder.
Extended packer detection heuristics (MPRESS, ASPACK, THEMIDA, etc.).
Added optional, feature-gated YARA CLI hook (detect local rules via yara binary).
Various test improvements and CI-friendly ILLUSION_TEST_MODE.
Many bug fixes and code cleanup.

-------------------------------------------------------------------

0.1.0 - Initial
Core deterministic triage engine: sandbox, monitor, dumper, report schema, basic heuristics.
