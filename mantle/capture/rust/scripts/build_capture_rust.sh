#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
RUST_ROOT="$(cd -- "$SCRIPT_DIR/.." && pwd)"

if ! command -v cargo >/dev/null 2>&1; then
  echo "cargo not found. Install Rust first: https://rustup.rs" >&2
  exit 127
fi

pushd "$RUST_ROOT" >/dev/null
cargo build --release -p capture-userspace
popd >/dev/null

echo "Built userspace binaries:" 
echo "  $RUST_ROOT/target/release/mantle_capture_ebpf"
echo "  $RUST_ROOT/target/release/mantle_capture_mitm_proxy"
