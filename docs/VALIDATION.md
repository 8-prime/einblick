# Implementation validation — 2026-10-12

## Management DNS — 2026-10-14

- Management configuration accepts CIDRs, literal IPv4/IPv6 addresses, and
  validated DNS hostnames. System-resolver results become individual host
  exemptions in the existing rule compiler, packet detector, and service-policy
  enforcement. DNS refresh runs outside capture/control, with bounded answers,
  lookup deadlines, and monotonic expiry of last-known addresses.
- **107 Rust tests passed**, with five pre-existing ignored checks. Coverage
  includes parsing, hostname normalization/rejection, mixed IPv4/IPv6 answers,
  deduplication, address replacement, static overlaps, lookup failures, stale
  expiry/recovery, capacity rejection, nonblocking refresh polling, allowlist
  precedence, service policies, and current API/session metadata.
- Strict Clippy and Rust formatting passed. Svelte check reported zero errors or
  warnings; all 13 frontend tests and the production build passed.
- `scripts/management-dns-smoke-test.py` uses an isolated mount namespace and a
  temporary hosts fixture to exercise the real system resolver and running mock
  server. It verifies startup IPv4/IPv6 exemptions, live address replacement over
  existing subnet bans, failed-lookup grace/expiry, activation safeguards, and
  recovery without restart or lost rules. Run after `cargo build` with:
  `sudo unshare --mount --propagation private -- python3 scripts/management-dns-smoke-test.py`.
- The XDP program and map ABI are unchanged. Enforcement validation uses the mock
  backend; privileged XDP and actual residential DDNS-provider propagation are
  not part of this check.

## Service protection — 2026-10-14

- Reviewed and reused the existing Rust/Svelte architecture, bounded SQLite
  workers, authenticated Origin/CSRF API, monitor commands, audit transactions,
  allowlists, rule compiler, XDP backend, and mock backend. Schema v4 preserves
  existing data and backs up v3 databases before migration.
- Implemented service/source/filter/policy CRUD, an editable observe-only OpenSSH
  template, file and journal collectors, persistent positions, normalized events,
  shared Rust playground/replay, independent attributed rule reasons, history,
  source/policy health, and a selectable generated pipeline. Replay counts are
  counterfactual estimates over retained normalized events, not proven prevention.
- **95 Rust tests passed**, with five pre-existing ignored checks (privileged XDP
  and NAT, two external DB-IP checks, and a manual SQLite resource measurement).
  Format, strict Clippy, diff whitespace, Svelte check (zero errors/warnings),
  four frontend test files, production build, and Python syntax checks passed.
- New coverage includes OpenSSH variants, IPv4/IPv6, extraction errors, regex
  budgets, timestamps, rolling windows, independent policies, duplicate filters,
  disabled inputs, side-effect-free simulation beyond 8 KiB, source path/symlink
  rejection, atomic cursor/event and rule/attribution rollback, configuration
  revision rejection, v3 backup/restart recovery, file rotation/truncation,
  journal cursor decoding, and bounded journal backlog progression.
- The existing HTTP smoke test passed auth, network/application observability,
  child capability/lifecycle checks, manual IPv6 rules, mode persistence, SSE
  shutdown, restart, history, audit, and emergency disable. Its debug peak RSS
  was **45,432 KiB** for the parent and **18,172 KiB** for the application collector;
  this short synthetic test is not a service-capacity or throughput measurement.
- `scripts/service-smoke-test.py` passed with actual appended file logs and SQLite,
  exercising two attributed policies, observe mode, warm-up decisions/cooldown
  recovery, management protection, global automatic enforcement, pure playground
  and historical replay, independent rule removal, restart deduplication,
  truncation health, emergency disable, and service deletion. Enforcement used
  the existing mock backend; no alternate banning implementation was introduced.
- Socket fixtures and HTTP smoke tests required running outside the filesystem/
  network sandbox after localhost listeners were initially denied. Live host
  journald permissions/vacuum/rotation and privileged XDP were not tested. The
  kernel program/ABI are unchanged. Browser automation surfaces were unavailable,
  so no rendered browser walkthrough was performed. Docker image construction was
  not run; the local Docker daemon socket denied access. The runtime Dockerfile
  includes journalctl and Compose documents optional read-only mounts without
  granting additional capabilities.

Setup, limits, security/recovery semantics, and architectural decisions are in
[SERVICE_PROTECTION.md](SERVICE_PROTECTION.md); API contracts are in [API.md](API.md).

## Traffic analytics — 2026-10-13

- Added an Overview country summary and Analytics country/network rankings by
  packets or bytes, hourly observed/passed/blocked timeline with data gaps, protocol
  mix, and TCP/UDP destination-port rankings. Shared ranges are 24 hours, seven
  days, and 30 days. Coverage distinguishes unavailable mappings, untracked source
  and transport detail, incomplete evidence, and missing retained hours.
- The authenticated summary endpoint folds hourly history on the read worker.
  A regression with over 4 MiB of raw buckets verified that the full range is
  summarized even when the raw history response truncates. Other regressions cover
  range validation, current country lookup, port/protocol distinctions, both metric
  leaders, tail accounting, and process-local Overview denominators.
- All 79 workspace tests passed (five existing privileged/manual/provider tests
  ignored). The two frontend aggregation tests, strict Clippy, Svelte checks,
  production frontend build, server build, and authenticated HTTP smoke checks
  passed. Browser surfaces and a browser executable were unavailable; visual
  browser inspection was not performed. No deployment or kernel changes were made.

## DB-IP Lite enrichment — 2026-10-13

- Added local country/ASN context to live source summaries and the source inspector,
  with independent database freshness/error status and DB-IP attribution in the UI.
  Downloads are enabled by default for live capture and disabled in mock mode.
- Deterministic tests cover IPv4/IPv6 and mapped IPv4, reserved/private addresses,
  untracked-IP API responses, invalid gzip/MMDB/type/build-month rejection, atomic
  replacement, cached restart, current-month download skipping, and a real local
  HTTP current-404/previous-month fallback followed by a corrupt update.
- Workspace tests passed: **75 tests**, excluding two privileged kernel checks,
  the manual SQLite resource check, and two provider-dependent enrichment checks.
  Format, strict Clippy, Svelte check (zero errors/warnings), frontend production
  build, and the updated HTTP smoke test passed. Mock mode created no database
  download directory and kept documentation addresses unenriched.
- Both provider-dependent checks were run separately and passed: real downloaded
  October 2026 files validated and returned IPv4/IPv6 country/ASN data; the running
  background updater downloaded both files over HTTPS and restored both after a
  simulated restart. Validation accepts DB-IP's ASN compatibility header.
- XDP code/ABI and detection/rule behavior were unchanged; the privileged kernel
  harness was not rerun. Browser automation surfaces were unavailable, so frontend
  verification comprises compiler/build and embedded HTTP checks. No deployment
  or long-running resource/throughput measurement was performed.

## NAT container attribution — 2026-10-13

- The collector now joins read-only host conntrack dumps with optional Docker
  container addresses, including containers without published ports and kernel
  WireGuard transports without process/PID ownership. `nat_container` is endpoint
  evidence; it does not identify applications carried inside encrypted tunnels.
- Regressions cover the observed Gluetun UDP NAT tuple, IPv6 TCP DNAT, changed
  destination ports, malformed/truncated/duplicate netlink attributes, nondefault
  zones, source/destination/protocol/peer-port mismatches, stale/future evidence,
  snapshot IPC round trips, and unchanged traffic counters.
- Formatting, workspace tests (70 passed), strict Clippy, Svelte check, and the
  frontend production build passed. Ordinary tests exclude the privileged XDP
  test, the new real-kernel NAT test, and the manual SQLite resource measurement.
- The isolated kernel harness now includes a real UDP SNAT exchange with a changed
  host port and validates the new conntrack dump using only NET_ADMIN. This
  privileged check has not run locally: root execution and iptables are unavailable
  in the current environment. No homeserver deployment or live Docker integration
  has been performed. Enable Docker socket discovery and rebuild/recreate the
  service to validate new traffic on the deployment.

## Application attribution — 2026-10-13

- Same-image child collector exercised against real unprivileged TCP/UDP sockets
  and proc metadata, including ownership and socket close. The actual child
  executable/IPC integration test verifies capability masks and no-new-privileges.
- Regression coverage includes specific/wildcard/local-versus-forwarded matching,
  configured label precedence, Docker public/private ports and protocols, stale
  and future evidence, child loss, bounded frames/text/candidate sets, exec/name
  changes, attribution budget saturation/recovery, schema-v2 backup/data preservation,
  idempotent minute/hour/live merges, pruning, and historical query saturation
  without reducing packet counts. Detection/traffic health stay independent.
- HTTP smoke test passed application labels and historical label changes,
  parent capability checks, real child startup, SIGKILL/reaping, healthy traffic
  after child loss, restart persistence, and existing auth/firewall/SSE checks.
  The final debug smoke-test peak RSS was **37,012 KiB** for the server and
  **12,836 KiB** for the child; input still has only three synthetic sources.
- Rust formatting, workspace tests (**52 passed**), Clippy with warnings denied, Svelte check
  (zero errors/warnings), and frontend production build passed. The privileged
  XDP test remains excluded from the ordinary suite. XDP program/ABI were unchanged;
  the privileged harness was not rerun in this session.
- The file-backed debug resource check now includes one application per each of
  **16,384 groups** (32,768 minute/hour traffic and matching attribution rows).
  After caching checkpoint statements, one batch took **4.215 s**, a 500-row
  query **79.43 ms**, and the response **253,597 bytes**. Allocated SQLite pages
  were **17,510,400 bytes**, with **17,674,832 WAL bytes** after commit. This is a
  synthetic batch, not a sustained throughput or maximum-capacity acceptance test.
- Docker image build could not run because the local Docker daemon socket was
  unavailable. No image deployment or production Linux 6.1/cross-user capability
  validation was performed. Browser automation surfaces were unavailable; frontend
  validation here comprises compiler/build and embedded HTTP checks.

Runtime setup and supported coverage are in `APPLICATION_ATTRIBUTION.md`. Exact
Host TCP-client process attribution, NAT outside the supported Docker/default-zone
mapping, and proxy upstream/log attribution
remain future extensions. Rootful Docker permission/LSM profiles, Docker daemon
integration on a live deployment, long-running process/port churn, and host
CPU/RSS/disk performance remain deployment validation tasks.

## Port-bank reclamation and source traffic detail

Current implementation checks (supersede the earlier verifier notes below):

- Rust workspace: **34 passed**, with the privileged kernel test and manual
  resource measurement excluded from the ordinary suite. Both were run separately.
  Format and strict Clippy checks passed.
- Svelte: zero errors/warnings; production build passed. Browser checks confirmed
  selectable IPv4/IPv6 sources, destination-port filtering, coverage messages,
  and the detail table. Screenshot: `target/ui-preview/source-detail.png`.
- Debug and release HTTP smoke tests passed, including authenticated source-detail
  access, IPv6 drops, malformed IP/limit rejection, health after control commands,
  live detail, and detail surviving graceful restart.
- eBPF compiled with nightly Rust **1.100.0 (2026-09-08)** and official
  **bpf-linker v0.11.1**. Embedded ELF validation and release build passed. The
  object is **15,656 bytes**; the release server is approximately **6.8 MiB**.
- Isolated privileged WSL kernel **6.6.114.1-microsoft-standard-WSL2** accepted the
  program and owned native/generic XDP links on veth. Both modes passed churn
  through 256 ports across successive 128-slot intervals, deliberate within-bank
  overflow and next-interval recovery, and exactly 1,000 concurrent port and
  SYN/ACK-association counts during repeated bank switches.
  UDP port zero, ICMP/no-port and fragment associations, RST indicators, bounded
  source-port samples, and association pass/drop counts were checked as well.
  Existing IPv4/IPv6,
  VLAN/fragment enforcement, IPv6 extensions, allowlist, expiry, emergency disable,
  attachment conflict, and SIGKILL detachment checks passed. Capabilities were
  BPF/NET_ADMIN/PERFMON, with NET_RAW for injection and no SYS_ADMIN.
- SQLite tests cover schema-v1 backup/data preservation, independent source
  associations, nullable versus real port zero, pagination/filtering, idempotent
  live/stored merging, hourly deltas, restart boundaries, pruning, and omitted
  intervals within an existing bucket. Monitor tests prove that detail loss alone
  does not suspend complete detectors, source loss still suspends bans, recreated
  source counters use a new baseline, and writer backpressure carries gap metadata.

The full-minute SQLite measurement used a file-backed database with **16,384
distinct groups** (32,768 minute/hour rows) on WSL, in a debug test. One checkpoint
took **2.252 s**; a 500-row query took **22.37 ms**, with **130,071 response bytes**.
Allocated SQLite pages were **5,079,040 bytes**, with **5,154,152 WAL bytes** observed
after commit (WAL auto-checkpointing can reuse this file). This is one synthetic
batch, not a measurement of the million-row cap or sustained production latency.
Run it with:

```sh
cargo test --locked -p einblick-core full_minute_resource_measurement -- --ignored --nocapture
```

Release mock smoke-test peak RSS was **27,344 KiB (26.7 MiB)**; debug was
**34,064 KiB**. Those tests have three synthetic sources. The conservative kernel
budget includes both association/port banks, per-CPU values and handshake maps;
the default estimate is approximately **16.9 MiB at two possible CPUs** and
**44.0 MiB at 16**. Actual allocation and maximum-capacity userspace memory were
not measured. Large host CPU counts can require reducing capacities at startup.

Docker Desktop's Linux engine was unreachable in this session, so the updated
image was not rebuilt locally. pnpm checks used installed **10.7.0** with automatic
package-manager switching disabled because the pinned **11.8.0** launcher was
missing; the frozen lockfile was retained. CI still uses the pinned pnpm and
nightly versions. No remote CI or homeserver deployment was performed.
NIC-specific behavior, Linux 6.1 verification, sustained 100kpps throughput,
two-vCPU performance and maximum-capacity memory/disk acceptance remain host
validation tasks. The veth tests establish functional behavior on the tested
kernel, not NIC throughput.

## Earlier validation record

The sections below record previous implementation stages; their statements about
runtime verification being unavailable predate the WSL checks above.

## Passed locally

- Rust workspace: **22 tests passed**, one privileged kernel test explicitly ignored.
- Targeted API regression: authentication, Origin/CSRF checks, logout, and asset-path
  traversal rejection passed.
- `cargo fmt --all -- --check` and Clippy with warnings denied passed.
- Svelte checks: zero errors and zero warnings; production Vite build passed.
- Kernel object: compiled successfully for `bpfel-unknown-none` using nightly Rust
  1.101.0 (2026-10-12) and the official bpf-linker v0.11.1 binary.
- Userspace release binary: built with embedded eBPF and frontend assets,
  approximately **6.8 MiB**. The corrected kernel ELF object is approximately **8.9 KiB**.
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
crash cleanup require privileged kernel tests and remain unverified locally.
The image and mock container were verified using rootless Docker; this does not
establish verifier acceptance or runtime attachment support.

## XDP verifier regression correction

Inspection of the original ELF confirmed that its `ingress` function ended with
a relocated call to `panic_bounds_check`, causing the verifier's
`last insn is not an exit or jmp` structural rejection.

Packet reads now return incomplete observations on missing bytes, without Rust
indexing panic paths. The XDP reader also compares each read pointer directly
with `data_end`, with bounded offsets, rather than relying on slice-length
comparisons to prove packet access to the verifier. The parsing rules remain
shared with the userspace slice reader.

The server's build script validates embedded ELF functions for panic symbols and
valid final EXIT/JMP instructions. An embedding build using the original object
was rejected by that check, and the corrected object passed it. Disassembly
confirmed direct packet-pointer bounds checks before packet loads. Workspace
tests, including malformed IPv6 extension lengths and every truncation of that
fixture, and Clippy passed after the changes.

The next verifier rejection, `R8 pointer -= pointer prohibited`, came from
calculating packet length as `data_end - data`. XDP now calls
`bpf_xdp_get_buff_len` (helper 188) once and reuses its scalar result for parsing
and byte counters. Packet loads retain their direct `data_end` bounds checks.
The embedding check requires this helper call; the object containing pointer
subtraction was rejected, while the rebuilt object passed. Disassembly confirmed
that the packet-length calculation now calls helper 188. The privileged harness
also checks global and per-source byte counts for an injected Ethernet frame;
these runtime assertions remain unverified locally.

The earlier successful Docker image build predates this correction. Corrected
runtime verifier acceptance and enforcement still require the privileged target
host. A static ELF check and compilation are not substitutes for that validation.

The subsequent `R5 tried to add from different maps, paths or scalars` rejection
occurred on the second iteration of Aya's `memset` fallback, while initializing
the parser's 24-byte stack value. bpf-linker's default ordered memory expansion
disables generic memset expansion, leaving calls to that fallback for both the
parser value and the 40-byte source counters. The eBPF crate's build script now
passes `--disable-expand-memcpy-in-order` so fixed-size operations compile to
loads/stores. Rebuilt object inspection confirmed that both memset call
relocations disappeared; the parser initialization uses three fixed 64-bit
stores. This setting applies to Docker and local Cargo builds alike.

The embedding validator rejects references to memory fallback functions while
allowing their unused exported definitions. An ELF regression test covers that
distinction for memset, memcpy, memmove, memcmp, and bcmp.

The next rejection, `R4 has pointer with unsupported alu operation`, occurred at
`r4 += r5` with a packet pointer and a known scalar offset of 14. Linux 6.1's
speculation sanitization supports stack/map pointers at that point, but rejects
packet pointers when `bpf_bypass_spec_v1()` is false. That predicate uses
`perfmon_capable()` (`CAP_PERFMON` or `CAP_SYS_ADMIN`), rather than `CAP_BPF` or
UID 0. This exposed an incomplete deployment capability list. Production Compose
and the isolated kernel harness now include `CAP_PERFMON` alongside `CAP_BPF`
and `CAP_NET_ADMIN`, while still dropping `CAP_SYS_ADMIN`. The test packet injector
additionally requires `CAP_NET_RAW`. Startup diagnostics name all three capture
capabilities.

The capability requirement was checked against the Linux 6.1
[verifier](https://github.com/torvalds/linux/blob/v6.1/kernel/bpf/verifier.c#L7440-L7473),
[BPF capability predicates](https://github.com/torvalds/linux/blob/v6.1/include/linux/bpf.h#L1676-L1698),
and [capability definitions](https://github.com/torvalds/linux/blob/v6.1/include/uapi/linux/capability.h#L366-L378).
Runtime acceptance with these changes remains unverified locally.

The later `invalid access to packet, off=2 size=1` rejection occurred after
IPv6 extension parsing. The verifier had checked a pointer used for TCP header
length, but the emitted TCP port load used a newly constructed packet pointer
with no known accessible range. A scalar IP-length comparison does not establish
a packet-pointer range for that load.

The first inline assembly reader kept the pointer addition, comparison and byte
load together, but used `pointer >= data_end` to skip a load at offset zero.
The subsequent `invalid access to packet, off=0 size=1` rejection exposed a second
issue: for a variable-offset pointer with fixed offset zero, Linux's
[range inference](https://github.com/torvalds/linux/blob/v6.1/kernel/bpf/verifier.c#L8879-L8901)
does not infer a readable range from that comparison.

The corrected reader adds the variable offset, then a fixed one byte, skips the
load when `pointer > data_end`, and loads at `pointer - 1`. That establishes the
one-byte range needed by the load. The whole sequence stays in one inline
assembly block so LLVM cannot separate or merge the check and load. A failed
check returns a sentinel that becomes `None`; the shared parser still reports
incomplete evidence. Inspection of the rebuilt ELF found all 53 non-stack byte
loads use this fixed-width pattern.

Embedding validation now enforces this reader pattern for ingress byte loads
outside the stack. It checks the fixed increment, matching pointer register,
comparison, skip distance, and load offset. Tests cover the previous zero-range
pattern and incorrect width/register/branch variants in both ELF byte orders.
An embedding build rejected the previous real object and accepted the rebuilt
object. This is a structural check, not a full kernel pointer-provenance proof.

The kernel harness now injects a TCP SYN after four differently sized IPv6
extension headers and verifies both its event and source blocking. The fixture
and every truncation passed the shared parser regression test. All 22 workspace
tests and Clippy passed (the privileged kernel test was skipped). The release
binary built with this object. An attempted isolated kernel run stopped at
`sudo: a password is required`, so runtime acceptance remains unverified.

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
