# Application attribution

Per-IP traffic shows local application/service candidates beside each destination
and port. Evidence is stored with history; reassigning a port does not relabel old
records. Counts belong to the whole row, not individual candidate applications.

Destination groups combine traffic across the selected range, so first/last seen
cover the whole group. Each incoming interval is attributed before grouping;
an initially unknown destination can gain application evidence from later traffic.
Earlier missing-attribution reasons remain alongside that evidence and apply to
part of the range. Newly discovered applications do not relabel old traffic.

## Enable automatic discovery

Use the existing single image and single Compose service. The updated production
Compose retains host networking and adds:

```yaml
cap_add: [BPF, NET_ADMIN, PERFMON, SYS_PTRACE, DAC_READ_SEARCH]
volumes:
  # Append to existing data/config mounts.
  - /proc:/host/proc:ro
```

Add this to an existing config; the example already includes it:

```toml
[applications]
enabled = true
proc_root = "/host/proc"
refresh_seconds = 2
stale_seconds = 10
batch_evidence_bytes = 8388608
docker_socket = ""
```

Host networking exposes sockets, not host processes. The proc mount supplies the
process view without `pid: host`. SYS_PTRACE permits cross-process metadata access;
DAC_READ_SEARCH permits reading other users' proc directories. These are powerful
inspection capabilities; the read-only mount is not a read-only security boundary.
The profile targets rootful Linux Docker without user namespace remapping.
LSM/hidepid restrictions can still prevent access and are disclosed in evidence.

After changing Compose mounts or capabilities, recreate the service so Docker
applies the new container configuration:

```sh
docker compose up -d --force-recreate einblick
```

`docker compose restart` restarts the existing container with its existing mounts
and capabilities. Check **Health → Application discovery** for the current state,
socket count, and errors; destination rows retain reasons from earlier traffic
and can still include `disabled` after discovery has been enabled.
Health shows `partial` when discovery finds sockets but reports scan/access errors,
with the number of sockets having identified owners and bounded error details.
`Collector or socket scan unavailable` can refer to one failed address-family/
protocol scan while other scans succeed; its diagnostic identifies which failed.
An unresolved socket interface index no longer aborts the rest of its scan. That
socket retains its binding index and is excluded from attribution until its name
can be resolved; it never becomes a listener matching arbitrary interfaces.
Other sockets from the same scan continue to provide application evidence.

On AppArmor hosts, Docker's `docker-default` profile permits ptrace-style metadata
access only between processes using that same profile. Host process namespace/fd
reads can therefore remain denied even with SYS_PTRACE and DAC_READ_SEARCH.
Check the host kernel journal for AppArmor denials involving `einblick`,
`docker-default`, or `ptrace`:

```sh
sudo journalctl -k --since "10 minutes ago" --no-pager | grep -E 'apparmor="DENIED".*(einblick|docker-default|ptrace)'
```

For a container-scoped diagnostic, append `apparmor:unconfined` to this service's
`security_opt` and recreate it. This removes AppArmor confinement from this
container; it does not disable AppArmor on the host. If ownership discovery then
works, use a custom AppArmor profile permitting the collector's host metadata
reads for a confined deployment. Target processes' own AppArmor profiles can
also impose access restrictions. The default policy is documented in
[Docker's AppArmor profile template](https://github.com/moby/profiles/blob/main/apparmor/template.go).

The Rust entrypoint starts a child of the same executable in internal collector
mode before creating threads or opening administrator secrets, SQLite, or XDP
descriptors. The child retains only inspection capabilities, plus NET_ADMIN when
optional Docker discovery is enabled to read host conntrack. The HTTP/monitor
parent clears SYS_PTRACE/DAC_READ_SEARCH and ambient capabilities and sets
no-new-privileges before creating runtime threads; it retains capture/enforcement
capabilities including NET_ADMIN. Bounded configuration/snapshots pass over framed
stdin/stdout pipes. No host service, second container, shell supervisor, additional
listening port, or separate binary is needed.

The child enumerates IPv4/IPv6 TCP listeners and bound UDP sockets through
NETLINK_SOCK_DIAG and joins socket inodes to `/host/proc/<pid>/fd`. It records
bounded process names, executable basenames, lifetime identities, and available
systemd/container identifiers. It does not read environments, full command lines,
or payloads. Discovery never runs on the packet-polling path.

A child exit is reaped and marks attribution unavailable. Restart the container
to recover: the parent cannot regain privileges to start another collector.
Traffic completeness, detection eligibility, blocking, and `/healthz` readiness
are unaffected by discovery failure. Shutdown and parent death terminate the child.

## Optional Docker discovery

Append a socket mount to the same Compose service:

```yaml
volumes:
  - /var/run/docker.sock:/var/run/docker.sock:ro
```

Set `docker_socket = "/var/run/docker.sock"` in `[applications]`, with discovery
enabled. The collector issues only discovery GETs for API version and running
containers. Each scan refreshes the full list, mapping TCP/UDP host/private ports
and known container addresses with exposed ports. It also collects container
addresses independently of published/exposed ports and joins them with a bounded
host NETLINK_NETFILTER conntrack dump. IDs identify container lifetimes;
names and Compose service labels are display metadata. Discovery has a three-second
timeout and 4 MiB response cap. Failed refreshes do not keep obsolete mappings current.

Socket access grants Docker daemon API access even with `:ro`; this is an explicit
opt-in. This release supports Unix endpoints. Without Docker API access, process
discovery and configured labels work, but automatic friendly container names and
published-port/NAT mappings are unavailable. Other container runtimes are not
resolved.

### Outbound container traffic and kernel WireGuard

The same Docker socket opt-in enables NAT attribution automatically; no `conntrack`
CLI package or extra container is required. The collector retains the existing
NET_ADMIN capability for read-only host conntrack dumps. SYS_ADMIN and entering
container network namespaces are not required.

For an outgoing flow such as `172.30.0.2:57034 → 152.233.20.208:1194`, Docker may
translate the source to `192.168.2.30:57034`. Einblick observes incoming replies to
that host address before reverse NAT. The collector joins the conntrack reply
with the original container address, then resolves it against Docker's current
address inventory. The row displays the container name (for example,
`arr-stack-gluetun-1`) with **Docker container via NAT** evidence (`nat_container`).
No published port, process PID, or userspace socket owner is needed, so this also
covers kernel WireGuard transports. It identifies a container/network endpoint;
it does not establish which process or application inside a shared network
namespace generated traffic, or label a protocol from its conventional port.
Encrypted VPN traffic remains attributed to the tunnel's container; identifying
applications carried inside it needs observation after decryption.

Both original and reply directions are supported for translated TCP/UDP endpoints,
including changed ports and IPv6. Matching requires the complete observed tuple,
including a sampled source port. Flows from nonzero conntrack zones are excluded
because capture records do not contain zone identity. Short-lived flows can be
missed between scans; stale/future mappings never relabel earlier traffic.

Health reports `nat_mappings`, and failures report `nat_unavailable` with a
conntrack diagnostic. Each dump caps traversal at 65,536 flows and one second,
with at most 4,096 container flow mappings per snapshot. Saturation reports
`scan_limit`; failed dumps discard their partial mappings. Evidence is indexed
and read from snapshots on the polling path, with no Docker or netlink I/O there.
Rebuild the image and recreate the service after enabling the Docker socket.
Earlier unknown history remains unchanged; new traffic can add container evidence
to the same destination group.

## Configured labels

Labels require no host inspection permissions and work with discovery disabled:

```toml
[[applications.services]]
name = "Nextcloud frontend"
destination = "192.0.2.10/32"
protocol = 6
port = 443
interface = "eth0" # optional
```

Protocol 6 is TCP and 17 is UDP. The longest destination prefix wins, then an
interface-specific rule. Equal-scope labels remain multiple candidates. They
display as configured services, not discovered processes. Restart after config
changes. Mock/demo configurations include labels for synthetic services.

## Meaning and limits

- Socket ownership and endpoint mappings indicate potential local applications,
  not delivery or connection success. Dropped packets never reach the service;
  passed packets can still be dropped later.
- Host wildcard listeners only match known local addresses; forwarded destinations
  cannot inherit a host application's name just because the port matches.
- Shared sockets, workers, socket activation, reuse-port, exec/name changes, and
  port reassignment can produce multiple applications. Observed timestamps are
  evidence bounds, not proof of continuous ownership.
- Evidence observed entirely after a traffic interval is not applied to it.
  Three bounded inventories retain nearby earlier observations. Periodic discovery
  can miss short-lived sockets/processes and changes between scans.
- TCP client connections are not collected yet. Some bound/connected UDP sockets
  provide candidates for incoming replies. Exact flow attribution and outbound
  counters need additional capture.
- Reverse-proxy processes are visible. The optional [Caddy integration](CADDY.md)
  adds per-IP host/path request evidence in the IP inspector; it does not identify
  upstream apps. Remote software is not identified. Unknown ports are not assigned names
  guessed from conventional port numbers.
- Unsupported transport, denied access, absent owners, stale evidence, saturation,
  and uncollected history are explicit reasons in rows and/or Health.

Scans cap socket endpoints at 4,096, processes at 16,384, descriptors at 131,072,
and proc traversal at 1.5 seconds. Frames cap at 2 MiB; saturation produces partial
evidence and retries on the next scan. Rows cap at eight evidence entries and
4 KiB serialized attribution. Additional serialized application entries have a
default 8 MiB budget per checkpoint batch, configurable from 256 KiB to 32 MiB;
fixed reason metadata remains when that budget is exhausted.

History keeps at most one sidecar per traffic row and deletes it with the parent
bucket under existing retention/row limits. Queries read at most 10,000 attribution
bucket records / 16 MiB of metadata, reporting `query_limit` without reducing
traffic counts. Responses remain capped at 4 MiB with continuation cursors.
These logical limits do not guarantee SQLite file size or replace host benchmarks.

Schema v2 upgrades transactionally to v3 after SQLite's backup API saves
`<database>.schema-v2-backup`. Rules, settings, audits, counters, and port samples
remain. Earlier history explicitly lacks attribution. V1 upgrades keep their
schema-v1 backup. Rollback restores the original backup and matching old image.
Preserve backups separately; migrations never overwrite an existing backup.
