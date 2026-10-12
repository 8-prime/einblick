#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
cargo +"${EINBLICK_BPF_TOOLCHAIN:-nightly-2026-10-12}" build --locked --release --manifest-path crates/ebpf/Cargo.toml --target bpfel-unknown-none -Z build-std=core
