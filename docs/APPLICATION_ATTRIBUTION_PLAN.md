# Application attribution for per-IP traffic

Status: core service attribution implemented locally, 2026-10-13. Deployment
remains one image and one container. See `APPLICATION_ATTRIBUTION.md` for actual
configuration, limits, and supported coverage, and `VALIDATION.md` for checks.
The design notes below retain the accepted plan and proposed future flow/log
extensions. Docker discovery uses periodic complete list refreshes in this release,
and the child communicates through framed pipes rather than a Unix socket pair.

## Intended result and scope

When inspecting an IP, show the local applications/services associated with its
traffic alongside the existing destination addresses, protocols, ports, and
counters. Examples: `sshd`, `nginx`, `postgres`, or a named container such as
`nextcloud-web`. Explain the source of each association and disclose uncertainty.

The working assumption is that "application" means an application on the monitored
server. Identifying software on a remote IP requires remote instrumentation or
application-level evidence; IPs and ports alone cannot establish its identity.
If remote identification is the primary requirement, revise the scope before
implementation. A browser User-Agent, for example, would be a reported identity,
not verification of the remote process.

Cover these distinct cases explicitly:

| Traffic case | Useful evidence | Initial behavior |
| --- | --- | --- |
| Incoming traffic to a host service | TCP listener or bound UDP socket and its owners | Show observed local service candidates |
| Incoming traffic to a published container port | Published endpoint mapping plus container metadata | Show mapped container/service |
| Incoming traffic to a reverse proxy | Proxy socket owner; later, access-log route/app identity | Show proxy first; upstream app only with separate evidence |
| Replies to a locally initiated connection | Connected socket ownership and full flow correlation | Candidate when available; reliable flow attribution is a later phase |
| Blocked packets, scans, closed ports, forwarded traffic | Endpoint configuration, if any | Show potential target or an explicit unknown reason |

Ingress capture also includes replies to outbound connections. A listener-only
implementation therefore does not cover every application that caused traffic.
Keep that limitation visible rather than assigning a generic port-based name.

## Existing integration points

- `crates/common/src/lib.rs`: `AssociationKey` groups source IP, destination IP,
  interface, protocol, and destination port. Source ports are only an eight-port
  sample in `AssociationCounters`; there is no complete five-tuple flow history.
- `crates/server/src/backend.rs`: converts collected XDP association banks into
  `TrafficRecord` values on the existing one-second poll.
- `crates/server/src/monitor.rs`: merges those records, checkpoints every ten
  seconds, and publishes live detail. This is the place to attach evidence before
  records lose their interval boundaries.
- `crates/core/src/traffic.rs`: shared records, merging, query, and response types.
- `crates/core/src/traffic_storage.rs` and `traffic_schema.sql`: schema-v2 minute
  and hourly association history with bounded storage and retry identities.
- `crates/server/src/api.rs`: authenticated `/api/v1/sources/{ip}/traffic` route.
- `frontend/src/App.svelte`: existing per-IP table and five-second refresh.
- `docker-compose.yml`: host networking but no host PID namespace or host proc
  mount; currently drops every capability except BPF, NET_ADMIN, and PERFMON.

XDP observes ingress before host firewall/NAT and socket delivery. Reading the
current PID in an XDP packet handler would identify execution context rather than
the application owning the traffic. Preserve the existing packet counters and
enforcement; application attribution should be a separate enrichment subsystem.

## 1. Define evidence, not a single unqualified application name

Introduce shared `ApplicationIdentity` and `ApplicationEvidence` models. Include:

- Display name, optional process name and executable basename, optional systemd
  unit, optional container ID/name and Compose service.
- Process identity using host boot ID, PID, and process start time, so PID reuse
  does not join unrelated lifetimes. Namespace and socket identities must also
  have explicit lifetimes; inode numbers alone are not durable identities.
- Evidence method: `socket_owner`, `published_port`, `configured`, or eventually
  `flow_socket` / `proxy_log`.
- Observed endpoint, network namespace, evidence observation times, expiry, and
  candidate identities. A matched local service is not proof of delivery.
- Structured statuses/reasons: attribution disabled, collector unavailable,
  permission denied, no matching socket observed, mapping unavailable, multiple
  candidates, unsupported transport, evidence stale, or evidence truncated.

Avoid numerical confidence percentages. Distinguish observed socket ownership,
configured mappings, and application-log evidence in human terms. A service name
derived only from a conventional port number may be an optional separate protocol
hint; it must never appear as a discovered process.

Keep candidate counts, metadata length, and serialized response size bounded.
Multiple candidates are legitimate: shared/inherited descriptors, socket
activation, SO_REUSEPORT, and service restarts can all create them.

## 2. Discover host socket owners outside the packet collector

Add an `application_collector` component with an immutable, timestamped snapshot
consumed by the monitor. It runs independently; socket enumeration and proc reads
must not delay packet polling or detector windows.

Use Linux `NETLINK_SOCK_DIAG` for IPv4/IPv6 TCP listeners and UDP bound sockets.
Join reported socket inodes to `/proc/<pid>/fd` socket links, then obtain bounded
process metadata from `comm`, `stat`, and, where permitted, `exe` and `cgroup`.
Do not ingest environment variables or full command lines by default.

Index candidates by network namespace, address family, protocol, local address,
local port, and applicable device binding. Match specific and wildcard binds
according to what the collector can establish. Account for IPv4-mapped IPv6 and
IPv6-only settings; if an option cannot be observed, retain uncertainty. Do not
associate arbitrary forwarded destinations with a host wildcard listener.

Start with a proposed two-second refresh and ten-second expiry, configurable and
subject to benchmarks. Publish successful scans atomically; distinguish partial
permission failures from a complete scan finding no owner. Maintain a short
bounded snapshot history for traffic interval correlation. A missing socket in
one scan does not prove a port was closed when a packet arrived. Socket creation,
exit, and port reassignment between scans are unavoidable MVP blind spots.

The current container cannot enumerate all host process owners just because it
uses host networking. Keep the existing image, entrypoint, and Compose service.
Implement the collector as a child process of the same Rust executable, started
automatically in an internal collector mode. No systemd installation, second
container, shell supervisor, or separately distributed binary is required.

Proposed process layout:

```text
Docker container (existing image)
  einblick --config /etc/einblick.toml
    |-- HTTP API, XDP monitor, SQLite writer
    `-- einblick --internal-application-collector
          socket diagnostics + host proc scan -> bounded metadata snapshots
```

Keep `network_mode: host`, and add a read-only host proc mount at `/host/proc`.
The collector reads `/host/proc/<host-pid>/...`; the container's ordinary `/proc`
remains unchanged. A host proc bind mount provides the required process view
without `pid: host`. Start with rootful Docker without user namespace remapping,
as required for this proposed host-access profile; report unsupported deployments.

Proposed additions to the existing Compose service, not a replacement file:

```yaml
cap_add: [BPF, NET_ADMIN, PERFMON, SYS_PTRACE, DAC_READ_SEARCH]
volumes:
  # Append to the existing data/config mounts.
  - /proc:/host/proc:ro
```

SYS_PTRACE covers cross-process proc access checks; DAC_READ_SEARCH covers
directory/file read permissions for other users' proc entries. These are powerful
host-inspection permissions, not a read-only security guarantee. Validate the
minimal set and LSM/hidepid behavior on supported hosts. Do not add privileged
mode or SYS_ADMIN for the host-listener feature.

Bootstrap the collector before creating the multithreaded Tokio runtime or reading
the password secret. Use an anonymous Unix socket pair with a narrowly defined,
bounded message protocol; give the child only its IPC endpoint and required
configuration, not database or XDP descriptors. The collector drops capabilities
unrelated to discovery; the parent clears the additional host-inspection
capabilities before starting its runtime threads. Validate this separation,
including effective/permitted/inheritable/ambient capability sets, no-new-privileges,
descriptor inheritance, and child restart behavior. This is partial privilege
separation within one container, not isolation equivalent to a separate service.

The parent supervises and reaps the child and marks evidence stale on failure.
On SIGTERM, stop/reap the child alongside the existing shutdown sequence. After
the parent drops inspection capabilities, a new child cannot simply regain them:
first release should report attribution unavailable until the container restarts.
Keep monitoring operational and expose the reason rather than repeatedly spawning
children without the required permissions. Independent privileged child recovery
would require a deliberately designed privilege broker and is outside the MVP.
Normal partial scan errors are handled within the collector without exiting.
Basic capture continues when attribution is off or unavailable; configured service
labels work without the proc mount or extra capabilities.

## 3. Add container and configured service mappings

Provide validated TOML service labels scoped by destination address/CIDR,
protocol, port, and optional interface, with explicit precedence and ambiguity
handling. Label these `Configured service`, not detected process ownership.
Changes have effective timestamps and must not rewrite prior history.

For automatic Docker discovery, extend the in-container collector to read container
list/inspect metadata and subscribe to lifecycle events, with periodic full
resynchronization. Export only names, IDs, Compose service labels, network
addresses, and published endpoints. Handle wildcard host bindings, protocol,
IPv4/IPv6, direct-routed container addresses, restarts, and removal. Mapping
`host:8080 -> container:80` must be resolved before looking for an owner of port
80 in the container. A `docker-proxy` owner should be described as a forwarding
layer when container mapping evidence exists.

Automatic Docker names and published-port mappings need an optional Docker API
endpoint, either an already available authorized endpoint or a daemon socket
mounted into this same container. Limit the collector's requests to list/inspect
and events. A read-only bind mount of a Unix socket does not restrict which API
calls can be sent through it; access to the daemon remains privileged, even when
the application's code only makes discovery requests. This is an explicit opt-in
deployment choice. No additional image or service is required. Without API access,
retain process attribution, available cgroup identifiers, and configured container
labels; do not promise automatic friendly container names or published-port
resolution. Do not ingest unrelated labels, environment variables, or secrets.

Container naming and published-port mapping are sufficient for the first Docker
release. Exact process ownership inside other network namespaces is a separate
extension with its own permission assessment. Unsupported runtime, NAT, routing,
or forwarding arrangements remain explicitly unresolved, never guessed from
host port numbers. Conntrack correlation can be evaluated later for arbitrary
DNAT; it is not required for the basic published-port feature.

## 4. Preserve historical evidence without changing counter semantics

Enrich each collected interval before minute aggregation. Keep the existing
`TrafficKey`, counters, and cursor ordering. Store attribution in sidecar records
keyed by the existing association and bucket, containing bounded evidence sets
and their observation intervals. An aggregate traffic row may have several
applications over its selected time range.

Do not divide or duplicate the aggregate packet/byte count among candidates.
For example, `nginx` followed by `caddy` on port 443 means "owners observed during
this range", not that each application handled every packet. Sampling and the
current grouping cannot produce exact per-application traffic totals. Evidence
only covering part of a traffic interval must retain that limited coverage.

Migrate schema v2 to v3 transactionally, following the existing SQLite backup API
pattern. Add attribution bucket records, normalized immutable identities where
useful, independent coverage metadata, and an attribution-start marker. Old rows
remain explicitly `Application attribution not collected`.

Persist traffic and matching attribution evidence in the same checkpoint
transaction, under the existing run/sequence retry identity. Roll up evidence
sets and time bounds to hours without copying counter totals. Merge committed
and live evidence using the same duplicate suppression as traffic. Never query
today's socket inventory to label historical traffic.

Use existing retention windows as maxima, with additional limits for attribution
rows, identities, per-row candidates, and metadata bytes. Prune evidence with its
traffic buckets and clean unreferenced identities. Overflow marks attribution
incomplete while preserving traffic counts. The proposed initial per-row candidate
limit is eight; other defaults must be selected after measuring the existing
256 MiB userspace target, disk growth, writer latency, and collector overhead.

## 5. Expose attribution in the existing API and dashboard

Add an optional, additive `applications` field to each traffic row, plus explicit
attribution status, evidence time ranges, and truncation/coverage information.
Keep traffic `complete` separate from attribution completeness. Extend authenticated
Health with collector mode, last successful refresh, stale/partial state, and
bounded failure reasons. Attribution failure does not change detection evidence,
blocking decisions, or base service readiness.

Add an `Application / service` column to the IP detail table. Show a concise
service name and evidence label, with expandable process/container details.
Useful display examples:

- `sshd — socket owner observed`
- `nextcloud-web — Docker published port`
- `nginx — socket owner observed; upstream app unavailable`
- `Multiple owners observed — nginx, caddy`
- `Unknown — application attribution not collected`

For dropped packets, describe a matching application as a potential target.
For partial evidence, show its limited observation period. Keep source-port
samples available, but do not use them as a substitute for full flow tracking.
Reuse the selected-IP refresh and existing authentication and response limits.
Escape names as text. Add application filtering only when it can be performed
server-side before pagination; it need not block the initial column release.

## 6. Extend coverage when needed

### Locally initiated connections and stronger flow correlation

Prototype a supplementary socket-lifecycle eBPF collector after the first service
release. Record ownership at task-context socket operations such as connect,
accept, and send/receive, using hooks verified on Linux 6.1 and the supported
Aya toolchain. Network callbacks alone do not establish the responsible PID.
Account for inherited/shared sockets, descriptor transfer, process exit, startup
bootstrap, UDP, and socket identity reuse. Benchmark before committing to specific
hooks; do not introduce mandatory kernel-version or capability upgrades silently.

Reliable matching needs a full five-tuple, namespace, and lifetime. Add a bounded
supplementary flow association map or event stream rather than expanding every
existing traffic group by source port. If reporting actual per-app counts,
collect counters per attributed flow with explicit loss/coverage reporting and
separate NAT correlation. Existing eight-port samples cannot reconstruct them.

Inbound replies can then identify a local client such as `curl` or a backup
service. Outbound byte/packet totals require a separate egress capture design;
the existing ingress totals must keep their meaning. XDP-dropped attempts still
cannot be claimed as delivered to a socket.

### Applications behind reverse proxies

Use a separate structured access-log adapter for Nginx, Traefik, or Caddy to expose
the virtual host/router/upstream application. This fits the existing roadmap for
HTTP log ingestion. Preserve log provenance, observation times, bounded retention,
and client-IP trust configuration. Keep request counts distinct from packet
counts. Route information alone need not require storing URLs or request payloads.
TLS port 443 shared by several apps cannot select an upstream from port metadata.

## Delivery order and acceptance checks

1. Evidence model, bounded configured labels, mock data, schema-v3 persistence,
   and API/UI column. Verify unknown/partial/multiple-owner displays and preserve
   existing counters and pagination.
2. Host socket collector and opt-in deployment. Verify TCP/UDP, IPv4/IPv6, exact
   and wildcard bindings, device constraints, socket activation, shared owners,
   PID reuse, process/port churn, scan races, denied proc access, collector failure,
   and stale evidence. Establish measured refresh/resource defaults.
3. Docker metadata adapter. Verify host/container port differences, address-
   specific and wildcard bindings, container recreation, IPv6/direct routing,
   lifecycle event loss/resync, and unresolved forwarding cases.
4. Historical/resource regression checks and documentation. Confirm an app
   changing on a port never relabels old traffic, mixed intervals do not fabricate
   per-app counts, v2 data survives migration, checkpoint retries/restarts remain
   idempotent, caps disclose omissions, and attribution failure does not suspend
   otherwise healthy detection. Exercise low-volume IPs outside the top 100.
5. Separately validate flow attribution and proxy-log extensions when their
   additional coverage is required.

Run existing Rust, Clippy, Svelte, and mock HTTP checks for implementation changes.
Extend isolated network-namespace kernel integration tests for real socket and
container scenarios, and measure collector CPU/RSS, database growth, and packet
poll latency under high process/socket churn and the existing traffic benchmark.
No tests are necessary for this planning-only document.

## Technical references

- [Linux socket diagnostics](https://man7.org/linux/man-pages/man7/sock_diag.7.html):
  socket endpoints, state, inode, and cookie information.
- [Proc file descriptors](https://man7.org/linux/man-pages/man5/proc_pid_fd.5.html):
  socket inode links and ptrace access checks.
- [Proc network information](https://man7.org/linux/man-pages/man5/proc_pid_net.5.html):
  network tables are scoped to a process's network namespace, not its owned sockets.
- [Docker published ports](https://docs.docker.com/engine/network/port-publishing/):
  host/container port translation, IPv4/IPv6, and routed networking.
- [Docker daemon security](https://docs.docker.com/engine/security/): discovery
  access to the daemon is a privileged deployment concern.
- [Linux sk_lookup hooks](https://docs.kernel.org/bpf/prog_sk_lookup.html): later
  transport-layer socket selection; established TCP/connected UDP bypass this
  hook, so it is not a universal traffic-to-process attribution mechanism.
