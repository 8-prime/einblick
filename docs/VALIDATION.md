# Implementation validation — 2026-10-12

## Passed locally

- Rust workspace: **18 tests passed**, one privileged kernel test explicitly ignored.
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
