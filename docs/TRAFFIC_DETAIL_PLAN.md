# Port-map reclamation and per-IP traffic detail

Status: implemented locally, 2026-10-12. See `VALIDATION.md` for verification and
remaining host performance checks. The design below records the accepted plan.

## Intended result

Old destination-port entries no longer exhaust kernel tracking indefinitely.
An administrator can select a source IP and inspect the destination addresses,
ports, protocols, TCP attempt indicators, and Einblick pass/drop decisions seen
for that IP, both live and over a selected historical range.

The plan uses the existing one-second collector, SQLite database, authenticated
API, and dashboard. It records aggregates, rather than packet payloads or a raw
packet log. Detail collection starts with deployment; the existing independent
source and port summaries cannot reconstruct earlier associations.

## Current implementation

- `crates/ebpf/src/main.rs` uses separate source and protocol/destination-port
  maps. The port value is only a cumulative packet counter.
- `crates/server/src/backend.rs` reclaims source entries after two idle minutes
  but never reclaims port entries.
- `crates/server/src/monitor.rs` computes deltas from cumulative counters. Simply
  deleting and recreating a port key can therefore suppress new counts when its
  replacement counter is smaller than the previous counter.
- Source and port insertion failures share one metric. Any increase currently
  resets all detector windows, although the detector consumes source counters
  and SYN events, not the global port map.
- The schema is version 1. Historical aggregates are JSON containing independent
  source and port lists; there is no queryable source-to-port association.

## 1. Reclaim port slots through interval collection

Replace the permanently cumulative port map with two bounded map banks. At a
normal one-second collection boundary:

1. Prepare an empty bank and switch the observation-bank selector.
2. Confirm that packet handlers using the previous bank have finished, using an
   explicit writer/quiescence handshake. Merely waiting a fixed duration or
   reading a map twice is insufficient.
3. Drain the previous bank's interval counters into userspace aggregates.
4. Clear that inactive bank before its next use.

Never clear or delete entries from the bank currently receiving updates. Bound
the handover work; if a bank cannot be safely drained, retain it and report the
affected detail interval as unavailable/incomplete. Source-counter and SYN-event
polling must continue without waiting indefinitely for detail collection.

This releases all collected port slots every interval, including ports used by
ordinary replies to outgoing connections. It also avoids deriving interval
counts by subtracting counters from unrelated key lifetimes. Historical totals
come from collected intervals, not from keeping kernel entries alive forever.
Keep kernel observation times monotonic; convert them to wall-clock timestamps
at collection with explicit handling of clock changes and interval boundaries.

Keep the existing configured port capacity as a per-bank limit. A burst involving
more distinct ports than one interval can hold can still exhaust capacity; this
must remain visible. Do not silently evict active entries to make that burst look
complete. Include both banks and the handshake maps in the startup memory budget.

Preserve the existing port summary's counter semantics through userspace
accumulation. Bound serialized results separately and report truncation. The
parsed key space is finite: TCP and UDP destination ports, plus protocol-only
entries where a transport port is unavailable.

Also track source-entry lifetimes in delta calculations. The source map already
expires entries, so a recreated source key must not inherit an old baseline.

## 2. Separate evidence health from detail health

Introduce independent insertion-miss counters for source, global-port, and
per-IP-detail maps. Preserve the combined miss total for compatibility.

Publish occupancy/capacity for each map, interval miss counts, cumulative miss
counts, last successful collection, and structured reasons such as source map
full, port map full, association map full, SYN loss, stale events, polling delay,
detector saturation, or detail-bank handover failure.

Use separate health scopes:

- Detection evidence: source packet/SYN counters, delivered SYN evidence, poll
  timing, and detector-window capacity.
- Traffic detail: global port summaries and source/destination associations.
- Persistence and enforcement: retain their existing independent health checks.

Missing detail alone must not suppress detectors whose actual inputs are
complete. Source-counter loss, SYN loss, stale evidence, and polling failures
retain conservative detection suspension. Prove this separation with tests
before changing automatic-ban gating.

The dashboard must explain the reason and scope. For example, a full association
map means some IP detail is missing; it does not justify claiming all automatic
decisions are suspended. Normal bank rotation is not a telemetry failure.
Control commands must preserve the last observed health rather than publishing
`telemetry_complete = false` unconditionally.

## 3. Capture source-to-destination associations

Extend the shared IPv4/IPv6 parser and kernel ABI to extract destination address,
source port, destination port, raw TCP flags, and explicit transport-parse
validity. Preserve safely extracted IP addresses for fragments or unsupported
transport headers. Unknown ports must be represented explicitly, rather than
being confused with a genuinely parsed port zero.

Add a second pair of interval maps for association counters. Group records by:

`source IP, destination IP, ingress interface, protocol, destination port/unknown`

For each group collect:

- Packet and byte counts.
- Passed and dropped packet counts according to Einblick's own XDP decision.
- TCP SYN-without-ACK, SYN/ACK, and RST counts.
- First and last observation times.
- Up to eight distinct observed source ports, plus a flag when this sample is
  truncated. Source ports do not become another unbounded grouping dimension.
- Parsing/evidence coverage information.

Use the same bank handover as the global port map. Start with a proposed 4,096
association entries per bank, configurable and subject to the full host-CPU/map
budget calculation. Final defaults must pass the existing 64 MiB kernel-map
budget; the extra banks must not be hidden from that estimate. Validate the
counter representation and bank sizes against realistic host CPU counts.

The capture remains ingress at XDP, before host firewall/NAT processing. Include
destination address and interface because traffic can target containers or be
forwarded. Label the disposition as "Passed by Einblick" or "Dropped by
Einblick"; it does not establish service acceptance or a successful connection.
TCP flags are evidence indicators, not proof of a completed TCP session. URL,
SSH-login, or HTTP-request details require a separate future log-ingestion feature.

## 4. Persist queryable detail with bounded growth

Migrate the existing database transactionally from schema version 1 to version 2.
Keep rules, settings, audit events, and existing aggregate history.
Create a recoverable SQLite backup using its backup API before migration; copying
only the main file while WAL is active is insufficient. The old binary rejects
schema version 2, so rollback restores that backup as well as the previous image.

Add normalized association bucket tables, indexed by source IP, resolution, and
bucket time, with the grouping dimensions and counters above. Store source-port
samples as bounded metadata. Add bucket-coverage metadata and a durable capture
start marker. Existing history is explicitly "detail not collected", not an
empty list implying that the IP contacted no ports.

Recommended initial retention and bounds:

| Setting | Proposed default |
| --- | --- |
| Association grouping retained in memory per minute | 16,384 rows |
| Minute association history | 7 days |
| Hourly association history | 90 days |
| Combined retained association history | 1,000,000 rows |
| Partial-minute checkpoint | Every 10 seconds, plus graceful shutdown |

The row cap is a logical storage bound, not a promise about exact SQLite file
size. Measure actual bytes, indexes, WAL growth, and write latency during
validation. Expose the row count and actual available history range. Make the
cap configurable and prune complete oldest buckets when it is reached; requested
retention is a maximum, and the cap may shorten availability.

Keep all captured groups within the minute limit, including low-volume probes;
do not keep only the top traffic senders. Once the limit is reached, continue
updating existing groups and explicitly count/flag omitted detail. Persist
coverage metadata even when no detail rows can be retained.

Checkpoint bounded batches in transactions, not one database job per packet.
Give each collector run and flush batch an identity so repeated delivery is
idempotent. Update minute and hour counters from newly committed deltas only;
do not repeatedly add the entire accumulated minute to the hour. Merge partial
minutes across graceful restarts. Preserve first/last times and coverage flags
through aggregation. An abrupt exit can lose an uncommitted checkpoint; mark
restart boundaries accordingly.

Keep database work off the packet-collection critical path with bounded pending
batches and explicit failure/backpressure reporting. Retention and query work
must not delay the one-second evidence poll. If needed, use a separate bounded
SQLite read connection under WAL so history queries do not occupy the writer
queue. Audit/persistence failures retain the existing ban-safety behavior.

## 5. Expose an IP detail view

Make source IPs selectable in both Overview and Traffic. Support opening a typed
IP directly so an administrator can inspect an address outside the current top
100 source list.

The detail view shows a selectable time range, destination addresses/interfaces,
protocol and destination port, packet/byte counts, TCP indicators, first/last
seen, and Einblick pass/drop counts. Link to audit/detection events for that IP.
Show available history range and explicit warnings for missing, truncated, or
uncollected detail. Service names may be hints derived from port numbers, never
claims about which application accepted the traffic.

Add an authenticated, bounded endpoint such as:

`GET /api/v1/sources/{ip}/traffic?from=...&to=...&resolution=minute|hour&cursor=...`

Validate/canonicalize IPv4 and IPv6, use parameterized queries, stable pagination,
and the existing 4 MiB response ceiling with an explicit continuation cursor.
Merge the current unpersisted bucket with stored detail without overlap. Keep
association rows out of the full snapshot/SSE stream; refresh only the selected
IP's detail on a bounded cadence. Filtering by protocol/destination port and
sorting must happen before pagination, not only in the browser.

## Implementation order

1. Interval port collection, lifetime-aware deltas, independent health counters,
   precise banner reasons, and the control-command health correction.
2. Extended parser/ABI, bounded association collection, and schema-v2 storage.
3. Source-detail API and dashboard, including history coverage and resource limits.
4. Integration, race, capacity, and resource validation; update README, example
   configuration, API documentation, and validation notes with measured results.

## Acceptance checks

- Sustained churn through more ports than the configured map capacity across
  successive intervals no longer causes permanent saturation or requires restart.
- A genuine within-interval capacity overflow reports the correct map and missing
  detail. Port/detail overflow alone does not create bans or unnecessarily suspend
  detectors with complete inputs; real detector-input loss still suspends bans.
- Concurrent updates during handover cannot be double-counted or erased by clearing
  an active bank. A failed handover is bounded and visible.
- Recreated source keys and repeated port keys keep correct interval counts.
- Two IPs contacting the same destination port retain distinct records; one IP
  contacting multiple ports and protocols returns the correct associations.
- IPv4/IPv6, multiple destination addresses/interfaces, UDP, ICMP/no-port traffic,
  fragments, TCP SYN/SYN-ACK/RST, and passed/dropped packets have correct detail.
- Existing schema-v1 data upgrades without losing rules/history. Flush retries,
  partial-minute restarts, hourly rollups, retention, caps, and unavailable history
  do not silently duplicate counts or turn gaps into zero traffic.
- Authentication, IPv6 addressing, pagination, filtering, live/history merging,
  and omission of IPs from the top-100 list do not prevent detail lookup.
- Run workspace tests, Clippy/format checks, Svelte checks/build, Docker build,
  extended mock HTTP tests, and the isolated privileged kernel harness. Use
  production capabilities and test generic XDP as well as native where available.
- Measure kernel/userspace memory, WAL/disk growth, collection latency, and churn
  behavior against the existing two-vCPU, 256 MiB userspace, 64 MiB kernel-map
  targets. Runtime kernel acceptance cannot be established by compilation alone.
