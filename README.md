# Einblick

Self-hosted ingress observability and basic intrusion prevention. Rust/Aya XDP,
SQLite history, and an embedded Svelte dashboard run in one container per server.

The MVP includes IPv4/IPv6 source and destination-port visibility, packet/byte
counters, TCP SYN attempt analysis, temporary automatic IP bans, manual permanent
and CIDR rules, expiring allowlists, historical charts, and an enforcement audit.
It starts in **observe mode**. HTTP log ingestion and subnet recommendations are
future work.

## Local container preview

Generate `secrets/admin-password` using the commands below, then run:

```sh
docker compose -f docker-compose.demo.yml up --build -d
```

Open <http://127.0.0.1:9080> and sign in with that password. This preview uses
synthetic traffic, its own data volume, and no BPF/network capabilities; it also
works with rootless Docker. Select its Docker context or set `DOCKER_HOST` to its
socket when using rootless Docker. Real network capture uses the deployment below.
Stop the preview with `docker compose -f docker-compose.demo.yml down`.

## Deploy

Requirements: rootful Docker Compose, Linux 6.1 or newer with BPF/XDP support,
x86-64, and an existing HTTPS reverse proxy. The configured interface must support
owned BPF XDP links. Native XDP is preferred; generic XDP is the optional fallback.
Einblick refuses legacy attachment and replacement of another XDP program.

```sh
cp einblick.example.toml einblick.toml
mkdir -p secrets
chmod 700 secrets
# Write a unique administrator password (at least 12 bytes) to this file.
# A password manager can generate it; the example uses a random secret.
umask 077
openssl rand -base64 32 > secrets/admin-password
```

Edit `einblick.toml`: set the actual host interface, the dashboard's public HTTPS
origin, and your administrator/VPN address in `management_allowlist`. The example
binds the web service to `127.0.0.1:9080`. This is separate from capture: XDP sees
all ingress on selected interfaces, including forwarded/container traffic before
host firewall/NAT handling.

For this rootful production stack, make the password file readable by UID 0:

```sh
sudo chown root:root secrets/admin-password
```

The container drops filesystem permission overrides, so ownership matters even
though it runs as root. A bind-mounted data directory, if used instead of the
named volume, must also be writable by UID 0. Rootless mock previews use the
invoking user's ownership instead.

```sh
docker compose up --build -d
docker compose logs -f einblick
```

The container uses host networking, `CAP_BPF`, `CAP_NET_ADMIN` and `CAP_PERFMON`,
unlimited memlock, a read-only root filesystem, and one writable `/data` volume.
`CAP_PERFMON` permits the verifier's packet-pointer arithmetic used by the parser
on supported kernels. It does not require privileged mode, bpffs pinning, or an
external database. Compose relaxes
seccomp because Docker's default profile can deny the BPF syscall; capabilities
and `no-new-privileges` still apply. SELinux/AppArmor policies must also permit
BPF loading and network attachment. Startup errors explain missing permissions,
map-budget failures, and verifier/attachment failures.

Example Nginx location inside an existing TLS server:

```nginx
location / {
    proxy_pass http://127.0.0.1:9080;
    proxy_http_version 1.1;
    proxy_set_header Host $host;
    proxy_set_header X-Real-IP $remote_addr;
    proxy_buffering off;
    proxy_read_timeout 1h;
}
```

Set `public_origin` to the exact HTTPS scheme and authority, without a trailing
slash. List only immediate proxy peers in `trusted_proxies`; only these peers can
supply `X-Real-IP` for login throttling. A proxy in its own container needs a
reachable host bind address instead of localhost. Update the healthcheck address
if changing port or binding to a specific address.

Sign in with the mounted password. Authentication uses Argon2id, short-lived
in-memory sessions (12 hours), HttpOnly/Secure/SameSite cookies, CSRF tokens, exact
Origin checks for mutations, and bounded login attempts. Password rotation means
replacing the secret and restarting; existing sessions are invalidated on restart.

## Enforcement and evidence

- **Observe:** records counters/detections and passes traffic, including stored
  block rules. Detection thresholds are configured in TOML and displayed in Health.
- **Manual:** applies address/CIDR allow and block rules. Adding a manual block
  explicitly enables blocking. Allowlist matches always win, regardless of prefix
  length; protected management ranges are loaded from configuration.
- **Automatic:** adds ten-minute individual-IP bans by default. Activation requires
  a configured management allowlist, acknowledgment of observe-mode evidence, and
  healthy storage/enforcement. CIDR and permanent bans remain manual.
- **Emergency disable:** switches off kernel blocking before writing restart
  settings. If persistence fails, the dashboard reports that restart state was not
  saved; resolve storage before restarting.

Defaults: 25 distinct TCP ports/source/60 seconds, 1,000 SYNs/source/10 seconds,
20,000 packets/source/second for three consecutive intervals, and an advisory
300 SYNs/source/port/minute detector. Retransmissions count as attempts, while
port scans deduplicate ports. `repeated_auto_ban` is disabled by default.

These are packet metadata signals. Ingress-only XDP cannot confirm TCP sessions,
closed ports, login failures, HTTP requests, or malicious intent. IPv6 extension
parsing is bounded to four headers; fragments, ESP, jumbograms, unsupported L2
headers, and malformed headers are counted as parsing limitations. Transport
analysis is unavailable for these packets; safely extracted source addresses
still participate in counters and enforcement. No payload is stored.

Counter maps are separate from the SYN ring buffer. Source, port, and IP-detail
capacity misses are reported separately. Lost/stale SYN events, source-map
misses, slow polling, and detector saturation reset detection windows and suspend
new automatic bans. Port/IP-detail misses mark traffic detail incomplete while
detectors with complete inputs continue. Health shows the reason, affected scope,
and collected map occupancy. The ring emitter caps SYN events at 10,000 per CPU
per second. Global packet counters continue independently.

Port and IP-detail maps use two banks. Each poll switches banks, waits for packet
writers to finish, collects the inactive bank, and clears its slots. Port churn
across intervals therefore no longer requires restarting the server. An interval
with more distinct keys than its configured capacity can still overflow; misses
remain visible and the next rotation frees those slots. Source entries idle for
two minutes are reclaimed, with new counter lifetimes tracked separately.

Rule updates populate an inactive map bank before switching the control word.
Temporary deadlines are enforced against kernel monotonic time, even between
userspace ticks. Prefix compilation inherits longer-lived ancestor rules so an
expired narrow prefix cannot mask an active broader rule. Rule status distinguishes
persisted intent from applied state; failed updates are reported and retried.
New automatic bans pause when audit storage or rule reconciliation fails.

Owned, unpinned links detach on shutdown or crash, allowing traffic. Active stored
rules and mode restore before attachment on restart. Enforcement is intentionally
absent while the service is down. Observe mode and manual mode persist too.

## History and resources

SQLite uses WAL and versioned migrations behind a bounded 64-job writer queue.
File-backed history reads use a separate read connection and a 16-job queue.
Minute traffic is retained for seven days; hourly summaries and security/audit
records for 90 days. Traffic buckets include observed/passed/dropped totals,
protocol/port detail, top 100 sources, and evidence completeness. Source detail is
approximate top-N: the difference between aggregate totals and retained source
counts is the other/untracked bucket. Raw packet events are not retained.

Overview packet/byte/pass/drop totals restore from SQLite on restart. They are
saved atomically with minute aggregates and at graceful shutdown, and survive
history expiration. Existing databases initially use retained hourly history;
already expired traffic cannot be reconstructed. An abrupt crash can lose the
uncommitted minute. Live rates and current source/port summaries cover the current
process; historical detail remains available through the source inspector.

Select a source IP in Overview or Traffic, or enter an IPv4/IPv6 address in
**Inspect a source IP**. The detail view associates it with destination addresses,
interfaces, protocols, and destination ports. It includes packets/bytes, TCP
SYN/SYN-ACK/RST indicators, Einblick pass/drop counts, first/last observation times,
bounded source-port samples, and related detection events. Filters run before
pagination. Unparsed ports are explicit; passing XDP does not mean a service
accepted a connection.

The detail table also shows local application/service candidates from recorded
socket ownership, optional Docker published-port/NAT container mappings, or
configured labels. NAT mapping also covers outbound container connections and
kernel WireGuard transports without a process PID. Discovery runs
as a child of the existing executable in the same image/container. Production
Compose adds a host-proc mount and inspection capabilities, which the HTTP parent
drops before creating runtime threads. Add `[applications] enabled = true` to an
existing config; the example already enables it. Historical evidence preserves
application changes on a port. Counts are not divided among candidates, and
ownership does not prove delivery. See [application attribution](docs/APPLICATION_ATTRIBUTION.md)
for deployment, Docker access, configured labels, coverage, and limits.

IP detail includes low-volume sources outside the top-100 summary, within
`association_capacity` (4,096 per bank) and `detail_minute_capacity` (16,384 distinct
groups per minute). Detail uses the configured seven-day minute and 90-day hourly
retention. `detail_row_limit` bounds their combined rows to 1,000,000 by default;
whole oldest buckets are pruned when full. This can shorten available history.
The view reports omissions, collection gaps, and expired/uncollected history.
The row cap limits logical growth, not SQLite file bytes; freed pages are reused.

Detail checkpoints run every ten seconds and on graceful shutdown, with at most
two pending batches. Retry identities prevent double counting, including hourly
rollups and partial-minute restarts. An abrupt crash can lose an uncommitted
checkpoint; the restart boundary is marked incomplete. Full queues retain gap
metadata and omitted packet counts. Legacy aggregate history still checkpoints
at minute boundaries and can lose an unfinished minute on abrupt exit.

Schema upgrades use SQLite's backup API before a transactional migration. A v1
database saves `<database>.schema-v1-backup`; a v2 database saves
`<database>.schema-v2-backup`. The current schema is v3. Rules, settings, audit,
and existing history remain. Rollback restores the original backup with the
matching old image. Earlier IP-to-port or application associations cannot be
reconstructed; capture starts with their respective deployments. Preserve the
migration backup separately.
Use SQLite's online backup API or stop the service before copying the database;
copying only the `.sqlite` file while WAL is active is insufficient.

History and event reads also cap serialized data at 4 MiB per query to bound response memory.

The initial target is a two-vCPU server, 100,000 ingress packets/second, 256 MiB
userspace RSS, and a separate 64 MiB kernel-map budget. These are validation
**targets**, not measured throughput claims. Map allocation is conservatively
estimated against the host's possible CPU count; a large host may require smaller
map capacities even when the container has a two-CPU quota. Compose caps total
container memory at 320 MiB to accommodate both budgets. Database disk usage
has retention limits but no fixed byte quota.

## IP country and network context

Overview includes a compact traffic-by-country ranking for the current process.
**Analytics** summarizes retained hourly traffic for the last 24 hours, seven days,
or 30 days: country and ASN/network rankings by packets or bytes, an observed /
passed / blocked timeline, protocol mix, and top TCP/UDP destination ports.
Select a country, network, protocol, or destination port to open **Query** with
that filter and the selected analytics time window. Query searches traffic detail
across all sources, combining country code, ISP/network organization, ASN, source
and target IP, target and sampled source port, protocol, interface, and preset or
custom time ranges. Filters run before pagination; results show application
candidates, TCP indicators, pass/drop counters, and first/last seen, with links to
the source inspector. The URL preserves the query for bookmarks and navigation.
Source-port matches use retained samples and show whole matching bucket/group
counts; they cannot isolate exact per-source-port volume. Detail coverage and
retention can differ from analytics source-summary rankings.

Analytics refreshes every minute and shows country coverage, incomplete evidence, and
hours without retained history. Country/network rankings use bounded top-100
hourly source summaries; unavailable mappings and other/untracked sources are
explicit. The current database maps historical IPs, so geography is approximate.

Live deployments automatically download the free [DB-IP Lite country and ASN
databases](https://db-ip.com/db/lite.php), without an account or API token. Overview,
Traffic, and the IP inspector show approximate country, ASN, and network organization.
The inspector can enrich a public address even when no traffic history exists.
Health shows each database's monthly release/build date, last update check, and
download errors. This context never triggers or changes firewall rules.

Downloads run in the background over HTTPS while capture continues. Files persist
in `ip-enrichment/` beside the SQLite database (`/data/ip-enrichment/` in the example
deployment). Einblick reads MMDB files directly; there is no SQLite import or
per-IP request to DB-IP. A daily check downloads a new monthly release when needed.
If the current release returns 404, it tries the previous month. Downloads have
timeouts and size limits; gzip/MMDB contents, database type, IPv6 support and build
month are validated before each file is replaced atomically. Failed updates retain
the previous valid data and are retried at the next check. Partial country/ASN
availability and older releases are visible in Health.

Optional configuration (defaults shown):

```toml
[ip_enrichment]
enabled = true
directory = "" # Empty: beside the history database; or set an explicit directory.
check_seconds = 86400 # Between one hour and seven days.
```

Set `enabled = false` to turn off downloads and lookups. Mock mode always disables
enrichment, including downloads. Outbound DNS and HTTPS to `download.db-ip.com`
are needed to seed/update the databases; cached data works offline. The runtime
image includes TLS CA certificates. DB-IP Lite data is licensed under
[CC BY 4.0](https://creativecommons.org/licenses/by/4.0/); dashboard pages using it
link back to DB-IP as required.

These are current mappings, including when inspecting historical traffic; they
are not historical location evidence. Unmapped, private, local and documentation
addresses show unavailable context. Country is approximate and does not identify
the person behind a connection. Lite data has reduced coverage/accuracy compared
with DB-IP's commercial datasets. Country and network identity do not establish
malicious intent; use observed traffic and service logs when deciding to ban.

## Develop and validate

Use pnpm, not npm, for the frontend. The pinned version is in its package manifest.
Install Rust stable, nightly-2026-10-12 with `rust-src`, and the official prebuilt
[bpf-linker v0.11.1](https://github.com/aya-rs/bpf-linker/releases/tag/v0.11.1) on PATH.
[Aya's XDP guide](https://aya-rs.dev/book/programs/xdp) describes the underlying
attachment/model; [kernel LPM documentation](https://www.kernel.org/doc/html/v6.9/bpf/map_lpm_trie.html)
describes prefix lookup.

```sh
./scripts/build.sh
cargo test --locked --workspace
cargo clippy --locked --workspace --all-targets -- -D warnings
pnpm --dir frontend check
```

Without kernel privileges, build the dashboard and a mock-only binary:

```sh
pnpm --dir frontend install --frozen-lockfile
pnpm --dir frontend build
cargo build --locked
# Create secrets/admin-password as above.
cargo run -- --config einblick.mock.toml
```

Open `http://127.0.0.1:9080`. Mock mode is labeled prominently; bans affect synthetic
traffic only. `pnpm --dir frontend dev` also offers frontend development with an
API proxy; set the mock `public_origin` to that development origin for login.
Production binaries built by the Dockerfile/build script embed both web assets
and eBPF. A plain Cargo build has no eBPF object unless
`EINBLICK_EBPF_OBJECT=/absolute/path/to/einblick-ebpf` is set; live capture fails
explicitly rather than silently using mock traffic.

```sh
python3 scripts/smoke-test.py
# Prepare binaries as your normal user, then test on a privileged Linux host:
./scripts/prepare-kernel-tests.sh
sudo env PATH="$PATH" unshare --net -- ./scripts/test-kernel.sh
```

The isolated kernel harness covers native/generic verifier loading/attachment,
port churn beyond capacity across intervals, explicit overflow/recovery,
concurrent port/association bank switching, IPv4/IPv6 and
VLAN/fragment source blocking, four IPv6 extension headers before TCP, SYN events,
allowlist precedence, expiry without
userspace cleanup, emergency disable, attachment conflict, and SIGKILL cleanup.
It refuses to run in the host network namespace and uses `setpriv` to load XDP
with the production capabilities (`CAP_BPF`, `CAP_NET_ADMIN`, `CAP_PERFMON`,
without `CAP_SYS_ADMIN`; the packet injector additionally needs `CAP_NET_RAW`).
The mock HTTP test covers sessions, manual rules, mode persistence, SSE shutdown,
restoration, history,
audit, and emergency disable. CI runs Rust/Svelte checks, builds the image, and runs the isolated kernel and mock HTTP tests on its privileged runner.

For performance acceptance, benchmark native XDP on a two-vCPU Linux host with an
external traffic generator: compare pass-through, observe, and block modes using
100kpps mixes of TCP SYN/ACK, UDP, IPv4/IPv6 and distributed sources for 60 seconds.
Record offered/received packets, counter deltas, event/map loss, CPU, RSS, kernel
map memory and time-to-detection. Repeat with scan/flood input and queue/map
saturation. A veth test validates behavior; it is not a NIC throughput benchmark.

See [docs/API.md](docs/API.md) for the HTTP contract and
[docs/VALIDATION.md](docs/VALIDATION.md) for checks performed during implementation.

## Service intrusion prevention

The Services dashboard configures journal/file sources, Rust regex filters, rolling
policies, an editable OpenSSH template, and observe-only or automatic whole-IP
protection through the existing XDP rule manager. The interactive playground is
side-effect-free; Overview includes a selectable generated pipeline and historical
replay estimates of potentially preventable events. Host log access is disabled
until explicitly configured. See [service protection](docs/SERVICE_PROTECTION.md)
for read-only mounts, activation, limits, recovery, and test commands.
