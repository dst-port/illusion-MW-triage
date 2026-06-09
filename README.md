# Illusion Sandbox

Lightweight malware triage sandbox. Run artifacts in an isolated process and collect dynamic and static evidence (drops, network contacts, memory/core dumps).

Quick start:

```bash
cargo test
cargo build --release
```

Run an artifact (Linux):

```bash
RUST_LOG=info ./target/release/illusion_sandbox analyze ./samples/suspect --pcap --yara-rules /path/to/rules.yar
```

Notes:
- Use `--pcap` to enable best-effort `tcpdump` capture (requires `tcpdump` and privileges).
- Use `--yara-rules /path/to/rules` to run an external `yara` CLI scan (set `YARA_RULES_PATH` internally).

Packaging:

There is a small helper script at `scripts/package_release.sh` that builds a release and archives the binary into `dist/`:

```bash
./scripts/package_release.sh
```

Features:
- Optional YARA integration via external `yara` binary (set `YARA_RULES_PATH`)
- Optional pcap capture using `tcpdump` (if available)
