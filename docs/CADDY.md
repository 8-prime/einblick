# Caddy request attribution

The IP inspector shows **Caddy · HTTP requests** with the requested host/domain,
path, method, HTTP status, and timestamp. This is evidence that Caddy logged a
request for that remote IP. It is independent of packet counts and socket-owner
candidates and does not identify the app behind a reverse proxy.

## Setup

Enable JSON access logging in each relevant Caddy site, for example:

```caddyfile
example.com {
    log {
        output file /var/log/caddy/access.json
        format json
    }
    reverse_proxy localhost:3000
}
```

The integration reads Caddy's standard `http.log.access` records, including named
access loggers, with `ts`, `request.remote_ip`, `request.host`, `request.uri`,
`request.method`, and `status`. Numeric Unix-second and RFC3339 timestamps work.
Keep those field names when customizing encoders. See Caddy's
[logging format](https://caddyserver.com/docs/logging) and
[log directive](https://caddyserver.com/docs/caddyfile/directives/log).

For Docker, append a read-only directory mount to Einblick's existing volumes:

```yaml
volumes:
  - /var/log/caddy:/host/caddy:ro
```

If Caddy runs in Docker with a named log volume, share that volume with Einblick
read-only at `/host/caddy` instead. Mount the containing directory so rotations
remain visible. Einblick's runtime user must have permission to read new files;
no Docker socket or extra Linux capabilities are needed for this integration.

Merge these settings into `einblick.toml`, retaining any existing log roots:

```toml
[service_logs]
allowed_roots = ["/host/caddy"]

[caddy]
enabled = true
log_paths = ["/host/caddy/access.json"]
poll_seconds = 5
retention_days = 7
row_limit = 100000
```

Use actual local paths for a native deployment. List up to 16 distinct files;
do not configure two aliases for the same file or multiple copies of each request.
Rebuild and recreate Einblick after updating its configuration/mounts:

```sh
docker compose up -d --build --force-recreate einblick
```

Inspect an IP under **Traffic**, or check **Health → Caddy integration** for each
source's last successful poll, read errors, backlog, skipped records, and file
gaps/resets. Integration failure does not change capture or blocking behavior.

## IP identity and stored data

Requests match the direct `request.remote_ip`, normalized for IPv4-mapped IPv6,
so the attribution refers to the same peer as the network source. Caddy's optional
`request.client_ip` is displayed separately when different. Behind a CDN or other
proxy, inspect the proxy's remote IP; requests are not reassigned to a forwarded
client address. Configure trusted proxy handling in Caddy if that separate client
field is needed. The integration does not read forwarded-IP headers itself.

Only host, path, method, status, timestamp, peer/client IP, and source file are
stored. Query strings, fragments, headers, cookies, bodies, and credentials in
headers are omitted. Host and path values are request metadata, not verified DNS
ownership. Paths can still contain sensitive data. Requests use the IP inspector's
time range; packet protocol/port filters do not filter log requests.

## Polling, retention, and recovery

New paths import the current file from its beginning in bounded batches, then
follow appends. The saved byte position and evidence commit in one transaction;
restart resumes without duplicate requests. A poll reads at most 256 KiB / 512
complete lines per file. Backlogs drain on subsequent polls. Partial final lines
wait for a newline. Invalid JSON, missing/unsupported fields, invalid timestamps,
records over 64 KiB, and paths over 2048 bytes are skipped and counted, allowing
later records to proceed. Future timestamps beyond five seconds are invalid.

Renamed files drain through a pinned descriptor before switching to the new file.
Truncation or changed bytes immediately before the saved offset reset the cursor
with a visible gap counter. Restart after rotation imports the current file and
reports a gap: rotated archives are not searched. Copy/truncate races, inode reuse,
and rapid rotations between polls can lose records. This is bounded best-effort
log history, not a lossless audit archive. Symlinks, traversal, and nonregular
files are rejected using the same restricted file opener as service logs.

Polling supports 1–3600 seconds; retention supports 1–90 days; the shared request
cap supports 128–1,000,000 rows. Oldest timestamps expire first. Retention runs
even with ingestion disabled, using the configured Caddy retention settings.
The row cap is applied after each poll, so one poll can temporarily add at most
512 rows per configured file beyond it. SQLite file size does not shrink with
logical deletions; use normal database maintenance/backups as needed.

Schema v6 adds separate request/source tables. Existing v5 databases get a
`<database>.schema-v5-backup` before the transactional migration. Existing packet
and application history stays intact. Preserve that backup for rollback with the
previous image.

## Validation

Run `cargo test --workspace`, frontend checks/build, then
`python3 scripts/caddy-smoke-test.py` after `cargo build`. The smoke test exercises
the actual background collector, file appends/rotation/truncation, authenticated
IP queries, persistence, restart, query stripping, and IP isolation with a mock
packet backend. It does not require a running Caddy instance.
