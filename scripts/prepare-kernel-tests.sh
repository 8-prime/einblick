#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
./scripts/build.sh
EINBLICK_EBPF_OBJECT="$PWD/crates/ebpf/target/bpfel-unknown-none/release/einblick-ebpf" cargo test --locked --no-run -p einblick --message-format=json > target/kernel-test-build.json
echo 'Kernel test binaries ready. Run sudo unshare --net -- ./scripts/test-kernel.sh'
