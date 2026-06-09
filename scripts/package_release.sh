#!/usr/bin/env bash
set -euo pipefail

# Build release and package binaries into dist/ (Linux + Windows GNU)

# Build Linux release
cargo build --release

# Try building Windows GNU target if installed
if rustup target list | grep -q 'x86_64-pc-windows-gnu (installed)'; then
  echo "Building Windows GNU target..."
  cargo build --release --target x86_64-pc-windows-gnu || true
else
  echo "Windows target x86_64-pc-windows-gnu not installed; skipping Windows build"
fi

mkdir -p dist

# Linux binary
LINUX_BIN=target/release/illusion_sandbox
if [ -f "$LINUX_BIN" ]; then
  cp "$LINUX_BIN" dist/illusion_sandbox-linux
  if command -v strip >/dev/null 2>&1; then
    strip dist/illusion_sandbox-linux || true
  fi
else
  echo "Linux release binary not found: $LINUX_BIN"
fi

# Windows binary (GNU target)
WIN_BIN=target/x86_64-pc-windows-gnu/release/illusion_sandbox.exe
if [ -f "$WIN_BIN" ]; then
  cp "$WIN_BIN" dist/illusion_sandbox-windows.exe
  if command -v x86_64-w64-mingw32-strip >/dev/null 2>&1; then
    x86_64-w64-mingw32-strip dist/illusion_sandbox-windows.exe || true
  elif command -v strip >/dev/null 2>&1; then
    strip dist/illusion_sandbox-windows.exe || true
  fi
else
  WIN_BIN2=target/x86_64-pc-windows-gnu/release/illusion_sandbox
  if [ -f "$WIN_BIN2" ]; then
    cp "$WIN_BIN2" dist/illusion_sandbox-windows.exe
    if command -v x86_64-w64-mingw32-strip >/dev/null 2>&1; then
      x86_64-w64-mingw32-strip dist/illusion_sandbox-windows.exe || true
    elif command -v strip >/dev/null 2>&1; then
      strip dist/illusion_sandbox-windows.exe || true
    fi
  else
    echo "Windows binary not found; skipping Windows packaging"
  fi
fi

cd dist
# Create a tarball containing available artifacts
tar -czf illusion_sandbox-$(date +%Y%m%d).tar.gz . || true
# Also create a Windows zip if zip is available
if command -v zip >/dev/null 2>&1; then
  zip -r illusion_sandbox-$(date +%Y%m%d)-windows.zip *.exe || true
fi
echo "Packaged dist/illusion_sandbox-*"
