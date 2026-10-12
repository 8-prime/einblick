#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
pnpm --dir frontend install --frozen-lockfile
pnpm --dir frontend check
pnpm --dir frontend build
./scripts/build-ebpf.sh
EINBLICK_EBPF_OBJECT="$PWD/crates/ebpf/target/bpfel-unknown-none/release/einblick-ebpf" cargo build --locked --release
