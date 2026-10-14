# API v1

All JSON endpoints use `/api/v1`. No CORS access is enabled. HTTP errors return
`{"error":"message"}`. Default mutation body size is 8 KiB; service routes allow 192 KiB. The API is single-admin;
no bearer API tokens or multiple roles are included in this MVP.

| Method | Path | Input / response |
|---|---|---|
| POST | `/auth/login` | `{ "password": "…" }` → `{ "csrf": "…" }`, session cookie |
| GET | `/auth/session` | CSRF token, management allowlist, configured detector thresholds |
| POST | `/auth/logout` | No body; destroys session; 204 |
| GET | `/snapshot` | Current `Snapshot` |
| GET | `/stream` | SSE `snapshot` events; `resync` when a subscriber falls behind |
| GET | `/rules` | Array of current `Rule` values |
| POST | `/rules` | `{ "network":"192.0.2.1/32", "kind":"block", "reason":"manual review", "seconds":600 }` |
| DELETE | `/rules/{id}` | Disable the desired rule |
| POST | `/mode` | `{ "automatic":false, "blocking":true, "acknowledged":false }` |
| POST | `/emergency-disable` | No body; disable kernel blocking before persistence |
| GET | `/history` | `resolution=minute\|hour`, `from`, `to` Unix seconds; up to 1,000 newest buckets, ascending; 4 MiB data limit |
| GET | `/analytics` | Optional `from`, `to` Unix seconds; default last 24 hours, maximum 30 days; compact hourly traffic summary |
| GET | `/events` | `limit` (default 100, max 200), `before` exclusive event ID cursor, optional exact source `ip`; newest first; 4 MiB data limit |
| GET | `/traffic` | Traffic detail across sources; combined filters and pagination below |
| GET | `/sources/{ip}/traffic` | Source association detail; parameters and response below |

Login requires an `Origin` matching `public_origin`. All other routes require the
`einblick_session` cookie. Mutations also require `X-CSRF-Token` and matching Origin.
SSE ends when the session becomes invalid or the server shuts down; reconnect and
refetch `/snapshot` after a `resync`. Sessions are lost on server restart.

`kind` is `allow` or `block`. Use an explicit CIDR, including `/32` or `/128` for an
individual address. Networks are canonicalized. `seconds: null` is permanent;
otherwise the range is 1 second–365 days. A nonempty reason is required (max 512
UTF-8 bytes). Duplicate active network/kind pairs are rejected. Allow and block
rules for the same network can coexist; allow takes precedence. Manual creation of
a block enables blocking. Automatic mode requires blocking, configured management
ranges, acknowledgment, and healthy storage/enforcement.

Control responses use `{ "accepted":true, "message":"…" }`. This means intent
was accepted, not that enforcement succeeded. Inspect `Rule.applied/error` and
`Snapshot.health.enforcement_ok`; failed kernel updates are retried. Storage/control
queue failures return errors. An emergency action can return an error after
successfully disabling kernel blocking if restart settings could not be persisted.

`Snapshot`: `at`, cumulative `totals`, process-local `session_totals`, latest-interval `rate`, `sources`, `ports`,
recent `detections`, `rules`, `automatic`, `blocking`, and `health`. `Totals` fields:
`packets`, `bytes`, `passed`, `dropped`, `parse_limits`, `event_loss`, `map_full`,
`source_misses`, `port_misses`, `association_misses`. `map_full` remains the combined
miss total. Detail miss rates follow the collected bank, while cumulative misses
include the active bank too.
Overview `totals` persist with minute aggregate checkpoints and graceful shutdown,
and are restored before the first observation. Existing databases bootstrap totals
from retained hourly history; history already expired before this upgrade cannot
be recovered. Once saved, totals survive history retention. An abrupt crash can
lose the current uncommitted minute. `session_totals`, source and port counters
restart with the process; rates use only new observations. Source rows include `ip`, `packets`, `bytes`,
`syns`, `generation` (counter lifetime); port rows include `protocol`, `port`, `packets`. Port zero means no parsed
transport destination. Rates are interval counts, not normalized bandwidth.
The legacy port summary also conflates a real port zero; association detail below
distinguishes it. The summary contains the top 100 cumulative collected ports.

Health adds `detection_complete`, `detail_complete`, `reasons`, and `maps`
(`name`, `used`, `capacity`). `telemetry_complete` combines the two scopes.
Missing port/association detail alone does not suspend detectors with complete
inputs. Storage/enforcement failures continue to suspend new automatic bans.
Commands preserve the latest telemetry health. Session metadata also includes
`detail_limits`: configured `minute_days`, `hourly_days`, and `row_limit`.

## Traffic analytics

`/analytics` summarizes whole overlapping hourly buckets, including persisted
minutes in the latest partial hour. It consumes one resolution only, reading each
bucket on the history worker without the raw `/history` endpoint's 4 MiB cutoff.
It excludes the uncommitted minute and does not change collection or retention.

The response has aligned `from`/`to`, `totals`, ascending `timeline` (hour `at`,
`packets`, `bytes`, `passed`, `dropped`, `complete`), and `countries`, `networks`,
`protocols`, `ports` rankings. Each ranking has `key`, `label`, `packets`, `bytes`.
Protocol and port rankings contain packet counts only; `bytes` is zero.
Country/network groups use current DB-IP mappings of the top 100 retained sources
per hour. `unknown` means retained sources without a mapping; `untracked` means
the difference between aggregate totals and retained source counts.
`country_mapped` and `source_tracked` contain packet/byte coverage counts.
Network rankings retain the ten packet leaders and ten byte leaders plus explicit
unknown/untracked groups; the remaining traffic is grouped as `other`.
Ports distinguish TCP and UDP and retain ten packet leaders plus `other`, `none`
(unparsed/no destination port, including legacy port zero), and `untracked`.
Protocol rankings include all retained protocols plus untracked detail.

`incomplete_buckets` counts retained hours with incomplete telemetry;
`missing_buckets` counts hours without retained buckets in the aligned range.
Missing hours remain absent from the timeline and must not be interpreted as zero
traffic. Counts and shares describe observations, not successful connections or
malicious intent. The dashboard supports 24-hour, seven-day, and 30-day ranges,
refreshes every minute, and allows packet/byte ranking of countries and networks.
Overview's compact country ranking uses process-local sources and totals instead.

## IP enrichment

Live `sources` in snapshots/SSE optionally include `ip_info`, and source traffic
detail responses include nullable `ip_info`, even for an untracked address. Its
fields are nullable `country_code`, `country`, `asn` (numeric), and `organization`.
Values come from local DB-IP Lite country/ASN databases; either can be available
independently. Private, local, documentation and unmapped addresses return no
context. IPv4-mapped IPv6 is canonicalized for lookup. Historical traffic detail
uses the current databases; enrichment is not persisted as historical evidence.
Legacy `/history` aggregates are not enriched.

`health.ip_enrichment` contains `enabled`, `state`, `country`, `asn`, nullable
`last_check`, and nullable `last_error`. Each database has nullable `release`
(`YYYY-MM`) and `build_at` (UTC Unix seconds). States are `disabled`, `waiting`,
`downloading`, `ready`, `stale`, `partial`, and `unavailable`. `ready` means both
databases match the current UTC month; `stale` means both are loaded but at least
one is older. `last_check` records the start of the latest check. Failed downloads
retain usable cached data, so `last_error` can coexist with available context.
Enrichment availability never changes telemetry completeness or ban eligibility.
Downloads are disabled in mock mode.

## Source traffic detail

`GET /api/v1/sources/{ip}/traffic` accepts canonicalizable IPv4/IPv6, including a
URL-encoded IPv6 address. Authentication uses the same session cookie as snapshots.

| Parameter | Meaning |
|---|---|
| `from`, `to` | Inclusive UTC Unix seconds; default last 24 hours; nonnegative range, at most 90 days |
| `resolution` | `minute` (default) or `hour`; counts include entire overlapping buckets |
| `protocol` | Optional IP protocol number, 0–255 |
| `port` | Optional parsed destination port, 0–65535; zero is a real port zero |
| `limit` | Default 100; 1–500 association rows per page |
| `cursor` | URL-encoded opaque `next_cursor` from the previous page; retain the same filters/range |

Rows group by destination address, interface, protocol and destination port,
ordered stably by those fields. Each includes `source`, `destination`, `interface`,
`protocol`, nullable `port`, `packets`, `bytes`, `passed`, `dropped`, `syns`
(SYN without ACK), `syn_acks`, `resets`, `first_seen`, `last_seen`, `source_ports`
(up to eight), and `source_ports_truncated`. Null ports mean no safely parsed
TCP/UDP header. Source ports are a sample; historical merging can return a smaller
sample with truncation flagged. No payload or connection-success claim is included.

Response fields: `rows`, optional `next_cursor`, optional `capture_started`,
optional `attribution_started`,
optional `available_from`/`available_to` (persisted bucket bounds), `complete`,
`omitted` (packet-detail omissions across the queried buckets), `stored_rows`
(global retained row count), and `warnings`. Coverage is collector-wide, because
an overflow can omit an association before its source is known in userspace.
Absence of rows with incomplete coverage is not evidence of no attempts.
`attribution_started` marks attribution records, including unknown or unsupported
results; it does not establish that automatic discovery is enabled or successful.

Stored and live batches merge in one SQLite snapshot; committed batch identities
prevent double counting. At most 500 bounded records remain below the 4 MiB
response ceiling. Detail is separate from SSE snapshots; the selected dashboard
view refreshes every five seconds and supports pagination and direct IP lookup.
Partial buckets, gaps, expiry, caps, and pre-deployment history are disclosed.

### Application evidence

Rows additionally include `application_attribution: { applications: [...], reasons: [...] }`.
Each application contains `id`, `name`, `method` (`socket_owner`, `published_port`,
`nat_container`, or `configured`), nullable `pid`, `process_start`, `executable`, `service`,
`container_id`, and `observed_from`/`observed_to` evidence time bounds. Rows retain
at most eight candidates and 4 KiB serialized attribution. Exec/name changes and
ownership changes are preserved; counters remain totals for the complete row.
`first_seen`/`last_seen` also cover the complete destination group. Attribution is
collected per incoming interval before grouping, so later traffic can add application
evidence to an initially unknown group. Earlier missing-attribution reasons remain
as partial-range history; they do not suppress new candidates.

Reasons include `not_collected`, `disabled`, `waiting`, `collector_unavailable`,
`stale`, `permission_denied`, `scan_limit`, `docker_unavailable`, `nat_unavailable`,
`no_matching_socket`, `unsupported_transport`, `multiple_candidates`, `truncated`,
and `query_limit`. Multiple reasons may coexist with observed candidates. Unknown
ownership does not prove a closed port or absent traffic. Old v2 rows are not
backfilled from current processes. Historical enrichment is bounded to 10,000
bucket records / 16 MiB of metadata per query; traffic counts stay complete when
that limit prevents further application enrichment.

`Snapshot.health.applications` includes automatic discovery `enabled`, `state`,
nullable `last_scan`, discovered `sockets` count, `owned_sockets` (sockets with at
least one identified owner), `reasons`, and bounded `diagnostics` strings.
`nat_mappings` counts observed TCP/UDP flow mappings to Docker containers; these
are container evidence and do not require a userspace socket owner. Conntrack
errors report `nat_unavailable` and a bounded diagnostic. NAT evidence matches
source/destination addresses, protocol, destination port, and an observed source
port; the mapping never assigns a container from a shared host port alone.
The `partial` state means scans produce evidence alongside discovery errors;
individual socket-scan diagnostics identify IPv4/IPv6, TCP/UDP, and the OS error.
Process-access diagnostics identify the inaccessible metadata stage. Attribution health
is independent of traffic/detection completeness and `/healthz` readiness.
See [application attribution](APPLICATION_ATTRIBUTION.md) for deployment and limits.

`Rule`: `id`, `network`, `kind`, `reason`, `actor`, `created`, optional `expires`,
`enabled`, `applied`, optional `error`. Timestamps are UTC Unix seconds. Expired or
removed rules disappear from the live list during pruning; their audit remains.

`Aggregate`: bucket `at`, `totals`, bounded `sources` and `ports`, `complete`.
`Event`: monotonic database `id`, `at`, `kind`, structured `detail`. Event kinds
include `detection`, `rule_created`, `rule_removed`, `mode_changed`, and
`enforcement_reconciled`. Detection detail includes `ip`, `kind`, `evidence`,
`eligible`, `at`; eligibility alone does not imply a ban was applied.

`GET /healthz` is unauthenticated and reports only `{ "ready":true|false }` (200 or
503). It requires healthy storage/enforcement and an observation within five
seconds. Detailed health is authenticated. The executable's `--healthcheck`
checks this endpoint, defaulting to `127.0.0.1:9080`, overridable by
`EINBLICK_HEALTH_ADDRESS`.

## Traffic query

`GET /traffic` shares the source inspector's range, resolution, limit, and evidence
metadata. Optional filters combine with AND: exact `source` and `destination`
IPv4/IPv6 addresses, `interface`, numeric `protocol`, target `port`, sampled
`source_port` (ports 0–65535), `country` (case-insensitive two-letter code or
`unknown`), numeric `asn`, and `organization` (case-insensitive substring, max
200 bytes). Country and ASN use current enrichment, never firewall policy.
Unknown query parameters are rejected. Defaults: last 24 hours, minute resolution,
100 groups; maximum 90 days and 500 groups. Pick hourly resolution beyond minute
retention. Filters apply before pagination to stored and uncommitted traffic.

The response extends `TrafficPage` with `sources`, an IP-keyed map of current
`IpInfo` or null. Rows sort by `(source,destination,interface,protocol,port)`;
`next_cursor` encodes that tuple and is opaque to clients. Send it as `cursor`
with unchanged filters/range. Each page is a fresh read; recent traffic can change
between pages. The source inspector keeps its existing four-field cursor.
Responses remain bounded to approximately 4 MiB.

Source-port matching checks bounded samples in each bucket. Matching buckets
contribute their entire traffic counts; missing/truncated samples can hide
matches. All time filters include whole overlapping buckets. Query counts may
differ from country/ASN analytics based on top-100 source summaries. Coverage,
omissions, expired history, and source-port limitations remain explicit.

## Service protection

Service endpoints use the same session, Origin, and CSRF protection. These routes
allow mutation bodies up to **192 KiB**; the 8 KiB limit remains on existing routes.
`/services/playground` and historical replay return 429 when both evaluation
workers are occupied. Limits and activation semantics are documented in
[SERVICE_PROTECTION.md](SERVICE_PROTECTION.md).

| Method | Path | Input / response |
|---|---|---|
| GET | `/services` | Array of saved service configurations |
| POST | `/services` | Configuration → saved service, generated ID/revision; observe-only forced on |
| GET | `/services/templates` | Editable template configurations; initially `openssh` |
| GET | `/services/{id}` | `{service, source_health, policy_health, events, decisions, access}`; latest 200 events/decisions |
| PUT | `/services/{id}` | Complete configuration with current revision → incremented revision; stale writes rejected |
| DELETE | `/services/{id}` | Soft delete configuration; 204; attributed rules retained until expiry |
| POST | `/services/playground` | `{service, source_id, input, spacing_seconds:1}` → pure Rust match/policy simulation |
| POST | `/services/preview` | `{source}` → `{lines, timing}`; bounded read-only preview |
| POST | `/services/{id}/history-simulation` | Complete draft → `{simulation, limited, from, to, caveat}`; retained-event policy replay |
| POST | `/services/{id}/sources/{source}/reset` | No body; reset read position to current end, increment revision, audit; 204 |

Configuration example (all IDs inside a service are stable local strings):

```json
{
  "id": 0,
  "revision": 0,
  "name": "Authentication",
  "description": "Host authentication failures",
  "enabled": true,
  "observe_only": true,
  "scope": "source_ip",
  "sources": [{
    "id": "auth-file",
    "name": "Authentication log",
    "enabled": true,
    "input": {"kind": "file", "path": "/host/logs/auth.log"},
    "filters": [{
      "id": "failed-password",
      "name": "Failed passwords",
      "enabled": true,
      "patterns": ["Failed password for (?P<subject>\\S+) from (?P<source_ip>[0-9a-fA-F:.]+) port \\d+"],
      "event_type": "authentication_failure",
      "ip_capture": "source_ip",
      "subject_capture": "subject",
      "timestamp_capture": null
    }]
  }],
  "policies": [{
    "id": "repeated-failures",
    "name": "Repeated failures",
    "enabled": true,
    "observe_only": true,
    "event_types": ["authentication_failure"],
    "threshold": 5,
    "window_seconds": 300,
    "ban_seconds": 600
  }]
}
```

Journal input is `{"kind":"journal","unit":"ssh.service"}`. File paths are
constrained by operator-configured `service_logs.allowed_roots`; journal access
requires `service_logs.journal_directory`. Service/individual policy observe flags
must both be false, global automatic/blocking modes enabled, and current health
complete before any live decision can create a rule. `scope` currently only
accepts `source_ip` (whole IP, not a service port).

Match results contain line number, filter ID, status (`matched`, `ignored`, or
`extraction_failed`), zero-based pattern index, normalized `event`, and `error`.
Normalized events preserve event/observation times, timestamp origin, service,
source/filter, IP, event type, optional subject, and raw evidence. Playground
spacing supplies synthetic timestamps where a filter lacks a timestamp capture.
An extraction failure makes the batch ineligible for simulated bans, matching
live source-gap safeguards.

Simulation returns `matches`, per-IP `counts`, `decisions` (policy hits with count,
window and intended duration), `potentially_preventable`, `source_counts`,
`filter_counts` (keys `source_id:filter_id`), `policy_counts`, and `timing`.
Historical replay uses saved normalized events and current policies; it does not
reapply changed filters to raw historical text. `limited` indicates the 10,000-row
or 4 MiB sample limit; `caveat` explains incomplete/counterfactual evidence.
Simulation never writes to SQLite or sends enforcement commands.

A service decision returns immutable triggering `hit`, decision `status`, optional
`rule_id`, and the current joined existing `Rule`. Statuses are `observe_only`,
`incomplete_evidence`, `allowlisted`, `global_observe`, `health_suspended`,
`already_active`, or `pending` (a rule was created). `pending` describes the
original decision: use the joined rule's enabled/applied/error/expiry fields and
global allowlists to determine its current effective enforcement status.
Rule actors are `service:{id}:policy:{policy_id}` and reasons include service and
policy names. Existing `rule_created`, `enforcement_reconciled`, mode, and removal
audit entries remain; service-specific audit kinds are `service_saved`,
`service_deleted`, `service_source_reset`, and `service_decision`.
