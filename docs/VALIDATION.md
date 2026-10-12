# Implementation validation — 2026-10-12

## Passed locally

- Rust workspace: **17 tests passed**, one privileged kernel test explicitly ignored.
- Targeted API regression: authentication, Origin/CSRF checks, logout, and asset-path
  traversal rejection passed.
- `cargo fmt --all -- --check` and Clippy with warnings denied passed.
- Svelte checks: zero errors and zero warnings; production Vite build passed.
- Kernel object: compiled successfully for `bpfel-unknown-none` using nightly Rust
  1.101.0 (2026-10-12) and the official bpf-linker v0.11.1 binary.
- Userspace release binary: built with embedded eBPF and frontend assets,
  approximately **6.8 MiB**. The kernel ELF object is approximately **8.7 KiB**.
- Both debug and release mock HTTP smoke tests passed: login, static dashboard,
  IPv6 manual block, mode persistence, graceful shutdown
  with an SSE client, restart restoration, stored history, audit events, and
  emergency disable.
- Release mock smoke-test peak RSS: **27,804 KiB (27.2 MiB)**. This is a short test
  with three synthetic source addresses; it is not a worst-case memory result.
- Docker Compose configuration and shell/Python script syntax validated.
- Docker multi-stage image build passed, including pnpm checks/build, the eBPF
  object, and the release application. The rootless local preview started via
  `docker-compose.demo.yml` and its container healthcheck passed.
- Container HTTP checks passed: embedded dashboard, authentication, sample
  traffic, healthy storage, initial observe mode, logout, and session invalidation.

Unit coverage also includes IPv4/IPv6/VLAN parsing, fragments and truncated
headers, SYN-versus-SYN/ACK classification, scan deduplication and window expiry,
consecutive flood evidence, allowlist precedence, overlapping CIDR deadlines,
activation safeguards, audit-write failures, and merging partial-minute writes
without double-counting hourly totals.

## Not verified locally

Runtime XDP verifier acceptance, real packet pass/drop behavior, and owned-link
crash cleanup could not be executed: root access via sudo requires a password.
The system Docker daemon is stopped and starting it requires sudo authentication.
The image and mock container were verified using a temporary rootless daemon;
the privileged production Compose deployment remains unverified. Successful
compilation does not establish verifier acceptance or runtime attachment support.

The running preview's Docker socket is
`unix:///tmp/einblick-docker-runtime/docker.sock`. To manage it in this session:

```sh
export DOCKER_HOST=unix:///tmp/einblick-docker-runtime/docker.sock
docker compose -f docker-compose.demo.yml ps
docker compose -f docker-compose.demo.yml down
```

The daemon and its image/data storage are under `/tmp`; this local preview is not
installed as a service and should not be expected to survive a reboot.

The isolated privileged harness and CI workflow are provided for these checks.
Prepare binaries as a normal user, then run:

```sh
./scripts/prepare-kernel-tests.sh
sudo unshare --net -- ./scripts/test-kernel.sh
```

The CI workflow was created but has not been run remotely in this session.

The 100,000-packets/second target, CPU overhead, full-capacity memory behavior,
queue/map saturation on real traffic, and NIC-specific native/generic attachment
remain unmeasured. See README for the performance acceptance procedure. Do not
interpret mock traffic results as an ingress-throughput benchmark.
