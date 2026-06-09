# illusion-sandbox

illusion-sandbox is a deterministic binary triage engine written in Rust. The project is designed to be cross-platform, with the current implementation targeting Linux; a Windows backend will be implemented later using platform-specific mechanisms. This document describes what the tool does, the analysis sub-tools it relies on, and the artifacts it produces.

What the tool does

- Validates incoming artifacts against a filename→SHA256 whitelist (TOML-backed).
- Executes artifacts in an isolated, hardened environment and captures bounded `stdout`/`stderr`.
- Observes runtime behavior with low-latency monitoring to detect transient processes and file-descriptor drops.
- Collects execution evidence and attempts memory/core dumps (ordered fallbacks).
- Performs lightweight static extraction (ELF entry point snippet and simple packer detection on Linux).
- Emits a deterministic `report.json` with artifact metadata, execution metadata, evidence locations, and deterministic verdict fields.

Platform details

- Linux (current):
	- Sandbox: `firejail` with hardened flags.
	- Monitoring: `/proc` inspection for processes and file descriptors.
	- Dumps: try `gcore`, then `gdb`, then a ptrace-backed region extractor.
	- Static parsing: crate-based parsers (ELF via `goblin`) and simple packer heuristics.

- Windows (planned):
	- Sandbox: platform-appropriate isolation (Windows Job objects, AppContainer, or Windows Sandbox) will be used instead of `firejail`.
	- Monitoring: Win32 process and handle APIs and Debugging APIs for low-latency observation.
	- Dumps: use `MiniDumpWriteDump` (dbghelp) or Debug APIs; platform-specific fallbacks will be implemented.
	- Static parsing: PE-aware parsers (crate alternatives) will be used for Windows binaries.

Sub-tools and system utilities used for analysis (examples)

- Linux: `firejail`, `gcore`, `gdb`, `/proc` (procfs), optional `readelf`/`objdump`.
- Windows (planned): `MiniDumpWriteDump`/`dbghelp`, DebugActiveProcess, Job objects or AppContainer-based isolation.

Key internal components

- `whitelist` — filename→SHA256 policy storage and lookup.
- `sandbox` — executes artifacts under isolation and captures bounded IO.
- `monitor` — low-latency runtime monitor detecting transient drops and dropped files.
- `dumper` — evidence collector with ordered dump fallbacks.
- `elf` / `pe` — static extraction for ELF now, PE support planned for Windows.
- `hash` — streaming SHA-256 computation for large files.
- `report` — assembles `report.json` and references evidence files.

Primary outputs

- `report.json` — structured triage report with metadata, deterministic verdicts, and evidence paths.
- Memory/core artifacts and extracted memory-region files.
- Captured `stdout`/`stderr` and any collected dropped file evidence.

Quick example (adjust to the CLI implementation)

```bash
cargo build --release
./target/release/illusion-sandbox analyze /path/to/artifact --out /tmp/analysis-run
```

Test mode (CI-friendly)

You can run the dynamic-analysis path in a CI-friendly "test mode" which skips `firejail` and the privileged dump/ptrace steps. This is useful for integration tests and developer runs without requiring elevated permissions.

Enable test mode by setting the `ILLUSION_TEST_MODE` environment variable to `1` (or `true`):

```bash
ILLUSION_TEST_MODE=1 cargo test --test integration_dynamic
```

When `ILLUSION_TEST_MODE` is set the runner will execute the target directly (no `firejail`) and will skip monitor/dumper threads; artifacts are still written under `runs/<name>-<ts>/` and a `report.json` is produced.

Hunt & Quarantine

The CLI provides a one-shot hunting command to scan paths for suspicious files using the heuristic set (filename masquerade, packer markers, entropy, whitelist lookup). Use `--quarantine` to move suspicious files into a quarantine directory.

Example:

```bash
# scan /tmp and /home for suspicious files and quarantine matches
cargo run -- hunt /tmp /home --quarantine --whitelist ./whitelist.toml
```

The hunt run writes a JSON report under `hunt_reports/<timestamp>/hunt_report.json` and quarantined items are moved under `quarantine/`.

Platform support

Linux backend is implemented (sandboxing via `firejail`, procfs-based monitor, dumper fallbacks). A Windows backend is scaffoled but not fully implemented; Windows-specific dumping and monitoring will be added in a follow-up.

Build-time confusables (optional)

The repository contains a small `build.rs` helper that writes `src/impersonation_confusables_gen.rs` at build time. This file is a placeholder by default but can be replaced by a richer generator that parses the Unicode CLDR `confusables.txt` to produce an embedded mapping for better masquerade detection.

To supply your own mapping, add a custom generator or replace `src/impersonation_confusables_gen.rs` before building. The code prefers generated mappings at runtime and falls back to a built-in conservative set.

Features

- `yara` (placeholder): optional runtime YARA integration. Disabled by default — when enabling this feature you should add a compatible `yara` crate dependency and ensure `libyara` is available on the build host.
- `windows-backend`: placeholder feature for toggling Windows-specific build-time code.

If you enable the `yara` feature, be aware that the crate and native library requirements must be satisfied on the build machine.

Security and usage notes

This tool is intended for controlled forensic or triage environments. Memory dumping and attaching to running processes often require elevated privileges; run on isolated hosts with appropriate safeguards. The Linux backend uses `firejail` and procfs-based monitoring; the Windows backend will use platform-appropriate isolation and debugging facilities when implemented.

This README focuses on the tool's behavior, the sub-tools it uses for analysis, platform differences, and the artifacts produced.

**Release artifacts and repository hygiene**

- Keep the repository focused: commit source code and curated release binaries under `/release/`. Do not commit `target/` or other transient build artifacts.
- The repository history has been rewritten to remove previously committed `target/` build artifacts and other large files. If you have a local clone from before this rewrite, update it with:

```bash
git fetch origin --all
git reset --hard origin/main
```

- To create release binaries locally:
	- Linux (local build):

```bash
cargo build --release
cp target/release/illusion_sandbox release/illusion_sandbox-linux
```

	- Windows (recommended: build on Windows or use an appropriate cross toolchain):

```bash
# Option A: build on Windows with MSVC toolchain
# Option B: cross-compile on Linux with mingw toolchain
rustup target add x86_64-pc-windows-gnu
sudo apt-get install mingw-w64   # Debian/Ubuntu
cargo build --release --target x86_64-pc-windows-gnu
cp target/x86_64-pc-windows-gnu/release/illusion_sandbox.exe release/illusion_sandbox-windows.exe
```

- After adding release binaries, commit only the files under `/release/` and avoid adding `target/` into future commits. Use `git lfs` for very large release artifacts when appropriate.
