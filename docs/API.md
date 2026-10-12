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
| GET | `/events` | `limit` (default 100, max 200), `before` exclusive event ID cursor; newest first; 4 MiB data limit |

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
`packets`, `bytes`, `passed`, `dropped`, `parse_limits`, `event_loss`, `map_full`.
Counters restart with the process. Source rows include `ip`, `packets`, `bytes`,
`syns`; port rows include `protocol`, `port`, `packets`. Port zero means no parsed
transport destination. Rates are interval counts, not normalized bandwidth.

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
