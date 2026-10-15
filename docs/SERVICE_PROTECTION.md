# Service protection

Services is a dedicated dashboard section. Create a service or choose the editable
OpenSSH template, configure sources and filters, define policies, and save. The
Overview pipeline is generated from the current configuration; selecting nodes
opens their configuration and editing controls. Detection events, decisions, and
applied rules are separate views. Health and history refresh every five seconds.

## Safe activation

New services always start in observe-only mode, even if a create request asks to
enforce. The OpenSSH template also starts every policy in observe-only mode.
Verify your unit (`ssh.service` on some hosts, `sshd.service` on others), inspect
sample logs, and review the evidence. Disable the service and policy observe-only
flags, then enable **Automatic IP bans** in Firewall with its existing management
allowlist and acknowledgment. Detection enabled is separate from enforcement
requested. A service observe-only flag overrides every policy; a policy observe-only
flag applies to that policy alone. **Both must be off** for a service policy to
create a new ban. Observe mode continues collecting normalized events on
**Overview → Recent normalized detections** and threshold decisions in
**Decisions & Bans**, with no rule attached to observation-only decisions. Saving
observe-only settings does not remove existing bans: they expire independently
or can be removed in Firewall. Packet-based detectors run independently and are
controlled by global Firewall settings. Unsaved edits do not affect live behavior.
All decisions pass through the monitor's global mode, management and
rule allowlists, storage health, and enforcement health. Emergency disable affects
service bans through that same monitor.

The initial supported enforcement scope is **the entire source IP**, across all
ports. Service identity describes the reason for a ban; it does not narrow the
packet match. No application, URL, HTTP host, or SSH-only port matching is implied.
Future packet scopes require explicit support in the existing rule compiler/XDP
ABI. There is no second enforcer.

Disable/delete stops new decisions after any already serialized decision, but
leaves existing rules to expire. Individual rules can be removed in Firewall.
Each policy/service reason owns a distinct persisted rule. The existing compiler
merges equal IPs/CIDRs using the longest deadline; removing one reason cannot
remove an independent reason. Manual allowlists always take precedence. Removed,
expired, pending, failed, and applied rules are distinguished in Decisions & Bans.

## Container host-log access

Access is disabled by default. Configure explicit directories in operator-owned
TOML, for example:

```toml
[service_logs]
allowed_roots = ["/host/logs"]
journal_directory = "/host/journal"
```

Mount only the logs needed for these services, read-only:

```yaml
volumes:
  - /var/log:/host/logs:ro
  - /var/log/journal:/host/journal:ro
```

Prefer a smaller directory if your logging configuration provides one. Mount a
containing directory to support rename rotation; a single-file bind mount can
continue exposing the old inode. For volatile journals use `/run/log/journal`
instead. Set the journal directory to the mounted journal root. The runtime image
includes `journalctl`; no host systemd socket or daemon access is needed. Native
installations need the journalctl executable. If your deployment uses a non-root
user, grant the journal/log file's normal read group through container `group_add`
or ACLs on the selected directories. Do not add filesystem bypass capabilities,
mount the host root, or make Einblick privileged for log collection. The HTTP
parent still drops its existing host-inspection capabilities.

If `journalctl` is not found inside the container, check `dpkg-query -W systemd`.
An absent package means the running image lacks the runtime dependency; having
the Services UI only establishes the application version. The repository's final
Docker stage installs `systemd` and verifies `journalctl --version`; CI also runs
the command in the resulting image. Rebuild and recreate from the host checkout:

```sh
docker compose build einblick
docker compose up -d --force-recreate einblick
docker compose exec einblick journalctl --version
```

Use the same Compose file/project used for deployment. If a custom image or
Dockerfile is used, its final runtime stage also needs the package. Package
installation belongs in that image build; the repository runs containers with
a read-only root filesystem.

File sources require absolute regular-file paths beneath configured roots. The
reader walks pinned directory descriptors using `openat`, `O_NOFOLLOW`, and
`O_NONBLOCK`; symlinks, traversal, FIFOs, and devices are rejected. Globs are not
supported. Missing permitted paths can be saved for later deployment and display
an unavailable state. Journal sources accept a single validated `.service` unit.
The fixed `journalctl` executable receives structured arguments with
`--directory` and `--unit`; no shell or administrator-provided command executes.
Inaccessible directories, empty/incorrect units, malformed messages, oversize
batches, and expired cursors are visible failures. Use **Reset reading position**
on an unhealthy source to start at the current end; this is audited and restarts
policy warm-up. It intentionally discards the unread backlog.

## Collection and evidence

The background worker polls every two seconds independently of packet capture.
New sources begin at EOF/current journal cursor rather than banning from old logs.
File positions (device, inode, generation, byte offset, and prefix anchor) and
journal cursors are persisted in the existing bounded SQLite worker. A read
position and its normalized events commit atomically. Restart can resume reading
without recounting the same observation, but policy windows start empty and
require a full warm-up window. Warm-up policy hits remain visible as incomplete
evidence decisions; their cooldowns are cleared when trusted evaluation starts. A crash between checkpoint and decision can omit a
decision; recovery deliberately favors no ban over reconstructing uncertain state.

Rename rotation drains the old open descriptor before opening the new inode.
Truncation or prefix changes clear evidence. Copytruncate followed by rapid regrowth
with an identical prefix may be indistinguishable from an append between polls;
prefer rename rotation for reliable collection. Partial lines wait for a newline.
Extraction errors, invalid UTF8, oversized records, backlog, source failures,
late/future or out-of-order timestamps, database backpressure, and policy capacity
limits suppress new bans and restart warm-up for the whole affected service.
Disabled sources are excluded from its evidence requirements.

Observation identities deduplicate the same physical file record (including
alias paths/hard links), journal cursor, and repeated same-type/IP extraction by
multiple filters. Independently exported journal and text representations cannot
reliably be identified as the same underlying event; do not attach both copies of
the same stream to an enforcing policy. Identical text at different offsets is
retained, because repeated authentication failures often have identical text.
Each observation/type/IP has one source/filter attribution (first committed match).
OpenSSH can log several distinct failure records for one connection; thresholds
count matched records, not unique connections.

Each filter tries multiple Rust regex patterns in order and emits its first match.
The IP capture must parse as IPv4 or IPv6. Optional subject extraction is bounded;
optional timestamps accept Unix seconds or RFC3339. Journal timestamps are used
when no timestamp capture is configured; plain files otherwise use observation
time. Timestamp origin and observation time are preserved. Old syslog wall-clock
prefixes are not silently guessed into a year/time zone.

Policies independently count their chosen event types per IP inside a rolling
`(event_time - window, event_time]` window. A threshold decision has a cooldown
for that policy/IP equal to its configured ban duration. Configurations have
optimistic revisions; edits invalidate old in-flight checkpoints and decisions,
clear policy windows, and re-enter warm-up. Persisted events and decisions retain
their original attribution and evidence after edits/deletion.

## Repeat-ban escalation

Policies use a fixed `ban_seconds` duration by default. Enable **Escalate repeat
bans** on a detection policy to configure `ban_escalation`: `multiplier` (2–10),
`max_ban_seconds` (at least the base duration, at most 604,800), and
`reset_after_seconds` (1–31,536,000). For example, a 600s base with multiplier 2
creates bans of 600s, 1,200s, 2,400s, and so on, up to the cap. The sequence resets
when the interval since the last ban reaches the reset duration.

History belongs to one service/policy/source-IP combination and survives restart,
rule removal, and event-history pruning. It starts when escalation is enabled;
older fixed-duration bans are not reconstructed. Only new committed rules advance
the sequence. Observe-only, allowlisted, incomplete, suspended, and already-active
decisions do not advance it. Events during an active ban do not extend its deadline.
The decision history displays the effective duration of each created rule.

History and rule/decision/audit creation share one transaction. Expired history is
pruned; at most 65,536 history entries are retained globally. Capacity exhaustion
suppresses new escalating bans instead of silently losing repeat-offender state.
Service deletion clears its escalation state while existing rules keep their expiry.
Removing a policy or turning off its escalation also clears that policy's sequence;
turning it back on starts fresh. Disabling detection or enabling observe-only keeps
unexpired history. Changing the reset interval updates unexpired history relative
to its last ban; expired sequences are not revived. Base duration, multiplier, and
cap edits use the saved settings for the next ban without resetting the count.

## Playground and historical estimates

Edit regexes/capture names/event types and paste multiline text on Sources &
Filters. Evaluation is debounced and uses the real Rust parser and policy engine.
Each filter/line shows Matched (neutral), Ignored (muted), or Extraction failed
(amber), pattern index, IP, subject, and the complete normalized event. Simulation
lists counts, policy thresholds, and red **Would ban** decisions with duration.
Simulations apply repeat-ban escalation to their own hypothetical ban sequence,
starting fresh within the sample; they do not read live offender history. No
simulation writes an event, decision, cursor, audit entry, or enforcement rule.
Recent source preview is bounded and read-only. Its pasted journal text does not
carry journal timestamps; use timestamp captures or the explicit synthetic line
spacing to test policy timing.

Historical replay uses the latest retained normalized events against the current
policy draft and their recorded event timestamps. It does not reapply edited
filters to old text; unmatched historical lines are not stored. It shows source/filter event counts,
policy decision counts, and **potentially preventable log events** on the pipeline.
An event counts as potentially preventable when an earlier hypothetical threshold
placed that IP inside a still-active whole-IP ban. The triggering event itself is
not counted. All policies continue evaluating the recorded stream so their
independent thresholds remain inspectable. This is a counterfactual estimate,
not a count of proven attacks prevented. The replay ignores live observe flags,
global allowlists, network reachability, missing/ignored logs, and source gaps;
previously applied bans can also reduce the available records. Timestamp quality
and the bounded sample determine its usefulness. Editing the draft invalidates
the displayed replay. The response reports truncation and the sampled time range.

## Storage, limits, and architecture

Schema v4 adds `protected_services`, `service_sources`, `security_events`, and
`service_decisions` through the existing migration sequence. Existing v3 databases
get a `.schema-v3-backup` before migration. Schema v5 adds `service_ban_history`;
existing v4 databases get a `.schema-v4-backup` before migration.
Sources/filters/policies are bounded,
validated configuration JSON in service rows, following existing JSON persistence
patterns; source cursors and searchable events/decisions have separate tables.
Rule and decision creation and the existing rule/audit events share one SQLite
transaction, so an audit/attribution failure cannot leave an unattributed ban.
Service history follows `retention.event_days` and has global hard row caps:
100,000 normalized events and 10,000 decisions. Audit/rule persistence retains
its existing behavior. Time retention runs every minute even with no services.

Limits: 64 services, 8 sources and 16 policies per service, 32 regex patterns /
16 KiB pattern text per service, 256 patterns and 64 sources globally; 8 patterns per filter,
2 KiB per regex, 32 regex nesting depth, 128 KiB compiled size and 64 KiB DFA
cache per pattern. Policy state is bounded to 1,024 IP/policy keys, 8,192 samples,
and 1,024 cooldowns per service. Thresholds are 1–1,000 events, windows 1–86,400s,
and ban durations 1–604,800s. Filters do no banning.

Lines are at most 8 KiB; file reads at most 256 KiB / 512 entries per batch;
journal output at most 2 MiB with a three-second read deadline. Previews return
at most 100 lines / 128 KiB. Playground requests are at most 192 KiB, with 128 KiB
sample text / 1,000 lines and two concurrent evaluation workers. Historical
replay reads at most 10,000 events / 4 MiB. SQLite uses the existing bounded
64-job write and 16-job read queues. CPU-bound previews/simulations/file reads
use blocking tasks; live filters are compiled once per configuration revision.

`core::services` owns normalization, regex parsing, policies, templates, and pure
simulation. `core::service_storage` extends `Database`; `server::service_logs`
collects and checkpoints evidence; `server::service_api` uses existing authenticated
Origin/CSRF-protected routes; `Monitor::Action::ServiceDecision` owns enforcement.
Packet detectors continue running independently. Future sources can produce the
same normalized event model; additional templates need configuration rather than
special-case detection behavior. HTTP ingestion, weighted/cross-service scoring,
Caddy, custom commands, subnet escalation, and port-scoped rules are not implemented.

## Validation

```sh
cargo fmt --all -- --check
cargo test --workspace --locked
cargo clippy --workspace --all-targets --locked -- -D warnings
pnpm --dir frontend check
pnpm --dir frontend test
pnpm --dir frontend build
cargo build --locked
python3 scripts/smoke-test.py
python3 scripts/service-smoke-test.py
```

The service smoke test uses a real temporary log file and SQLite database with
mock packet enforcement. It exercises authenticated template/configuration,
actual append ingestion, two policies, observe mode, warm-up/cooldown recovery,
management protection,
automatic enforcement, pure playground/replay, independent rule removal, restart
cursor recovery, truncation, emergency disable, and deletion. Live host journald
permissions/rotation and privileged XDP acceptance require deployment validation.
