#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
if [[ $EUID != 0 ]]; then
  echo 'Run inside an isolated namespace: sudo unshare --net -- scripts/test-kernel.sh' >&2
  exit 1
fi
# Never create interfaces in the host network namespace.
if [[ $(readlink /proc/self/ns/net) == $(readlink /proc/1/ns/net) ]]; then
  echo 'Refusing to run in the host network namespace.' >&2
  exit 1
fi
ip link set lo up
ip link add eb-test type veth peer name eb-peer
ip link set eb-test address 02:00:00:00:00:01
ip link set eb-peer address 02:00:00:00:00:02
ip link set eb-test up
ip link set eb-peer up
test_binary=$(python3 - target/kernel-test-build.json <<'PYTHON'
import json,sys
for line in open(sys.argv[1]):
    item=json.loads(line)
    if item.get("reason")=="compiler-artifact" and item.get("profile",{}).get("test") and item.get("target",{}).get("name")=="einblick" and item.get("executable"):
        print(item["executable"])
        break
else:
    raise SystemExit("Run scripts/prepare-kernel-tests.sh as your normal user first.")
PYTHON
)
# Exercise production capabilities, including PERFMON for packet-pointer
# arithmetic, without SYS_ADMIN. NET_RAW is only for injected test frames.
setpriv --bounding-set=-all,+bpf,+net_admin,+perfmon,+net_raw -- \
  "$test_binary" --exact backend::kernel_tests::xdp_namespace_rules_and_counters --ignored --nocapture
# Verify crash cleanup with a real server process and an unpinned XDP link.
dir=$(mktemp -d)
trap 'if [[ -n ${pid:-} ]]; then kill "$pid" 2>/dev/null || true; fi; rm -rf "$dir"' EXIT
printf '%s\n' 'isolated-kernel-test-password' > "$dir/password"
cat > "$dir/config.toml" <<CONFIG
bind = "127.0.0.1:19080"
public_origin = "https://kernel-test.invalid"
interfaces = ["eb-test"]
database = "$dir/test.sqlite"
password_file = "$dir/password"
source_capacity = 128
port_capacity = 128
CONFIG
setpriv --bounding-set=-all,+bpf,+net_admin,+perfmon -- \
  ./target/release/einblick --config "$dir/config.toml" > "$dir/server.log" 2>&1 &
pid=$!
for i in {1..30}; do
  if EINBLICK_HEALTH_ADDRESS=127.0.0.1:19080 ./target/release/einblick --healthcheck; then break; fi
  sleep 0.2
done
EINBLICK_HEALTH_ADDRESS=127.0.0.1:19080 ./target/release/einblick --healthcheck
kill -KILL "$pid"
wait "$pid" 2>/dev/null || true
pid=''
ip -j link show eb-test | python3 -c 'import sys,json; x=json.load(sys.stdin)[0].get("xdp",{}); assert not x.get("prog_id"),x'
echo 'Kernel enforcement and crash-detachment checks passed.'
