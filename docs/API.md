# API v1

All JSON endpoints use `/api/v1`. No CORS access is enabled. HTTP errors return
`{"error":"message"}`. Maximum mutation body size is 8 KiB. The API is single-admin;
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
| GET | `/events` | `limit` (default 100, max 200), `before` exclusive event ID cursor, optional exact source `ip`; newest first; 4 MiB data limit |
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

`Snapshot`: `at`, cumulative `totals`, latest-interval `rate`, `sources`, `ports`,
recent `detections`, `rules`, `automatic`, `blocking`, and `health`. `Totals` fields:
`packets`, `bytes`, `passed`, `dropped`, `parse_limits`, `event_loss`, `map_full`,
`source_misses`, `port_misses`, `association_misses`. `map_full` remains the combined
miss total. Detail miss rates follow the collected bank, while cumulative misses
include the active bank too.
Counters restart with the process. Source rows include `ip`, `packets`, `bytes`,
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

Stored and live batches merge in one SQLite snapshot; committed batch identities
prevent double counting. At most 500 bounded records remain below the 4 MiB
response ceiling. Detail is separate from SSE snapshots; the selected dashboard
view refreshes every five seconds and supports pagination and direct IP lookup.
Partial buckets, gaps, expiry, caps, and pre-deployment history are disclosed.

### Application evidence

Rows additionally include `application_attribution: { applications: [...], reasons: [...] }`.
Each application contains `id`, `name`, `method` (`socket_owner`, `published_port`,
or `configured`), nullable `pid`, `process_start`, `executable`, `service`,
`container_id`, and `observed_from`/`observed_to` evidence time bounds. Rows retain
at most eight candidates and 4 KiB serialized attribution. Exec/name changes and
ownership changes are preserved; counters remain totals for the complete row.
`first_seen`/`last_seen` also cover the complete destination group. Attribution is
collected per incoming interval before grouping, so later traffic can add application
evidence to an initially unknown group. Earlier missing-attribution reasons remain
as partial-range history; they do not suppress new candidates.

Reasons include `not_collected`, `disabled`, `waiting`, `collector_unavailable`,
`stale`, `permission_denied`, `scan_limit`, `docker_unavailable`,
`no_matching_socket`, `unsupported_transport`, `multiple_candidates`, `truncated`,
and `query_limit`. Multiple reasons may coexist with observed candidates. Unknown
ownership does not prove a closed port or absent traffic. Old v2 rows are not
backfilled from current processes. Historical enrichment is bounded to 10,000
bucket records / 16 MiB of metadata per query; traffic counts stay complete when
that limit prevents further application enrichment.

`Snapshot.health.applications` includes automatic discovery `enabled`, `state`,
nullable `last_scan`, discovered `sockets` count, and `reasons`. Attribution health
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
