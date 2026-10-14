//! Bounded polling collectors. All filesystem permissions come from operator configuration.
use crate::monitor::{Action, Command};
use anyhow::{Context, Result, ensure};
use einblick_core::{Config, services::*, storage::Database, unix_now};
use serde::{Deserialize, Serialize};
use std::{
    collections::HashMap,
    fs::File,
    io::{Read, Seek, SeekFrom},
    os::{
        fd::{AsRawFd, FromRawFd},
        unix::fs::MetadataExt,
    },
    path::{Component, Path},
    time::Duration,
};
use tokio::{
    io::{AsyncBufReadExt, AsyncReadExt, BufReader},
    sync::{broadcast, mpsc, oneshot},
};
const BATCH_BYTES: usize = 256 * 1024;

/// Walk every component using pinned directory descriptors. Symlinks, devices,
/// FIFOs and traversal are rejected, including races after validation.
pub fn open_log(config: &einblick_core::config::ServiceLogConfig, path: &str) -> Result<File> {
    let path = Path::new(path);
    ensure!(
        path.is_absolute()
            && !path
                .components()
                .any(|c| matches!(c, Component::ParentDir | Component::CurDir)),
        "absolute log path without traversal required"
    );
    let root = config
        .allowed_roots
        .iter()
        .map(Path::new)
        .filter(|p| path.starts_with(p))
        .max_by_key(|p| p.components().count())
        .context("log path is outside configured service_logs.allowed_roots")?;
    let open = |dir: i32, name: &std::ffi::OsStr, flags: i32| -> Result<File> {
        use std::os::unix::ffi::OsStrExt;
        let name = std::ffi::CString::new(name.as_bytes())?;
        let fd = unsafe {
            libc::openat(
                dir,
                name.as_ptr(),
                flags | libc::O_CLOEXEC | libc::O_NOFOLLOW | libc::O_NONBLOCK,
            )
        };
        ensure!(
            fd >= 0,
            "cannot open log component: {}",
            std::io::Error::last_os_error()
        );
        Ok(unsafe { File::from_raw_fd(fd) })
    };
    let mut directory = File::open("/")?;
    for part in root.components().skip(1) {
        let Component::Normal(name) = part else {
            anyhow::bail!("invalid configured log root")
        };
        directory = open(
            directory.as_raw_fd(),
            name,
            libc::O_RDONLY | libc::O_DIRECTORY,
        )?;
    }
    let parts = path.strip_prefix(root)?.components().collect::<Vec<_>>();
    ensure!(!parts.is_empty(), "log path must name a regular file");
    for (i, part) in parts.iter().enumerate() {
        let Component::Normal(name) = part else {
            anyhow::bail!("invalid log path component")
        };
        directory = open(
            directory.as_raw_fd(),
            name,
            libc::O_RDONLY
                | if i + 1 < parts.len() {
                    libc::O_DIRECTORY
                } else {
                    0
                },
        )?;
    }
    ensure!(
        directory.metadata()?.is_file(),
        "log source must be a regular file"
    );
    Ok(directory)
}
pub fn validate_source(
    config: &einblick_core::config::ServiceLogConfig,
    source: &LogSource,
) -> Result<()> {
    match &source.input {
        SourceInput::File { path } => {
            open_log(config, path)?;
        }
        SourceInput::Journal { .. } => {
            ensure!(
                !config.journal_directory.is_empty(),
                "journal access disabled; configure service_logs.journal_directory"
            );
            ensure!(
                Path::new(&config.journal_directory).is_dir(),
                "configured journal directory inaccessible"
            );
        }
    }
    Ok(())
}
#[derive(Clone, Default, Serialize, Deserialize)]
struct FilePosition {
    dev: u64,
    inode: u64,
    offset: u64,
    generation: u64,
    anchor: String,
}
struct Entry {
    identity: String,
    line: String,
    at: i64,
    journal: bool,
}
struct Batch {
    entries: Vec<Entry>,
    cursor: String,
    complete: bool,
}
#[derive(Default)]
struct FileReader {
    file: Option<File>,
}
impl FileReader {
    fn read(
        &mut self,
        config: &einblick_core::config::ServiceLogConfig,
        path: &str,
        cursor: &str,
        now: i64,
    ) -> Result<Batch> {
        let current = open_log(config, path)?;
        let meta = current.metadata()?;
        let mut p: FilePosition = if cursor.is_empty() {
            FilePosition::default()
        } else {
            serde_json::from_str(cursor).context("corrupt persisted file cursor")?
        };
        let mut complete = true;
        let rotated = p.inode != 0 && (meta.dev() != p.dev || meta.ino() != p.inode);
        if p.inode == 0 {
            p = FilePosition {
                dev: meta.dev(),
                inode: meta.ino(),
                offset: meta.len(),
                generation: 0,
                anchor: String::new(),
            };
            self.file = Some(current); // New configurations start at EOF, never ban from old logs.
        } else if meta.dev() != p.dev || meta.ino() != p.inode {
            if self.file.is_none() {
                p = FilePosition {
                    dev: meta.dev(),
                    inode: meta.ino(),
                    offset: meta.len(),
                    generation: 0,
                    anchor: String::new(),
                };
                complete = false;
                self.file = Some(current);
            } else {
                // Keep draining the renamed descriptor before switching to the new file.
                let old = self.file.as_ref().unwrap().metadata()?;
                if old.len() <= p.offset {
                    self.file = Some(current);
                    p = FilePosition {
                        dev: meta.dev(),
                        inode: meta.ino(),
                        offset: 0,
                        generation: 0,
                        anchor: String::new(),
                    };
                }
            }
        } else if self.file.is_none() {
            self.file = Some(current);
        }
        let file = self.file.as_mut().unwrap();
        let len = file.metadata()?.len();
        let mut anchor = vec![0; 32.min(len as usize)];
        file.seek(SeekFrom::Start(0))?;
        file.read_exact(&mut anchor)?;
        let anchor = hex::encode(anchor);
        if len < p.offset || (!p.anchor.is_empty() && !anchor.starts_with(&p.anchor)) {
            p.offset = 0;
            p.generation = now as u64;
            complete = false;
            p.anchor = String::new();
        }
        if p.anchor.is_empty() {
            p.anchor = anchor;
        }
        file.seek(SeekFrom::Start(p.offset))?;
        let mut bytes = vec![];
        file.take(BATCH_BYTES as u64).read_to_end(&mut bytes)?;
        let mut entries = vec![];
        let mut start = 0;
        for (i, b) in bytes.iter().enumerate() {
            if *b != b'\n' {
                continue;
            }
            ensure!(
                i - start <= MAX_LINE,
                "oversize log entry; detection state incomplete"
            );
            let line = std::str::from_utf8(&bytes[start..i])
                .context("non-UTF8 log entry; detection state incomplete")?
                .trim_end_matches('\r')
                .to_owned();
            entries.push(Entry {
                identity: format!(
                    "file:{}:{}:{}:{}",
                    p.dev,
                    p.inode,
                    p.generation,
                    p.offset + start as u64
                ),
                line,
                at: now,
                journal: false,
            });
            start = i + 1;
            if entries.len() >= 512 {
                break;
            }
        }
        ensure!(
            bytes.len() - start <= MAX_LINE || start > 0,
            "oversize unfinished log entry"
        );
        p.offset += start as u64;
        if rotated
            && p.inode != meta.ino()
            && bytes.len() < BATCH_BYTES
            && entries.len() < 512
            && start < bytes.len()
        {
            // A renamed file cannot receive a completing newline reliably. Drop
            // its partial tail with explicit gap health, then switch next poll.
            p.offset = len;
            complete = false;
        }
        if len.saturating_sub(p.offset) > MAX_LINE as u64 {
            complete = false;
        }
        Ok(Batch {
            entries,
            cursor: serde_json::to_string(&p)?,
            complete,
        })
    }
}
async fn journal(
    config: &einblick_core::config::ServiceLogConfig,
    unit: &str,
    cursor: &str,
    now: i64,
    preview: bool,
) -> Result<Batch> {
    ensure!(
        !config.journal_directory.is_empty(),
        "journal access disabled; configure service_logs.journal_directory"
    );
    let mut command = tokio::process::Command::new("journalctl");
    command
        .args([
            "--directory",
            &config.journal_directory,
            "--unit",
            unit,
            "--output=json",
            "--no-pager",
            "--quiet",
        ])
        .kill_on_drop(true);
    if preview {
        command.args(["--lines=100"]);
    } else if cursor.is_empty() {
        command.args(["--lines=1"]);
    } else {
        command
            .arg(format!("--after-cursor={cursor}"))
            .arg("--no-tail");
    }
    command
        .env("LC_ALL", "C")
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::null());
    let child = command.spawn().context(
        "journalctl unavailable; install it and mount the configured journal directory read-only",
    )?;
    read_journal_child(child, cursor, now, preview).await
}
async fn read_journal_child(
    mut child: tokio::process::Child,
    cursor: &str,
    now: i64,
    preview: bool,
) -> Result<Batch> {
    let stdout = child.stdout.take().unwrap().take(2 * 1024 * 1024 + 65537);
    let mut reader = BufReader::new(stdout);
    let mut output = vec![];
    let limited = tokio::time::timeout(Duration::from_secs(3), async {
        let mut count = 0;
        loop {
            let mut line = vec![];
            let read = reader.read_until(b'\n', &mut line).await?;
            if read == 0 {
                return Ok::<_, anyhow::Error>(false);
            }
            ensure!(line.len() <= 65536, "oversize journal record");
            if output.len() + line.len() > 2 * 1024 * 1024 {
                return Ok(true);
            }
            output.extend(line);
            count += 1;
            if count >= 512 {
                return Ok(true);
            }
        }
    })
    .await
    .context("journal read timed out")??;
    if limited {
        child.kill().await?;
    }
    let status = tokio::time::timeout(Duration::from_secs(1), child.wait()).await??;
    ensure!(
        limited || status.success(),
        "journal inaccessible or cursor no longer available (journalctl {status}); inspect mount, group permissions, and retention"
    );
    let mut batch = decode_journal(&output, cursor, now, preview)?;
    batch.complete &= !limited;
    Ok(batch)
}

fn decode_journal(output: &[u8], cursor: &str, now: i64, preview: bool) -> Result<Batch> {
    let mut entries = vec![];
    let mut next = cursor.to_owned();
    let mut complete = true;
    for raw in output.split(|b| *b == b'\n').filter(|b| !b.is_empty()) {
        ensure!(raw.len() <= 64 * 1024, "oversize journal record");
        let v: serde_json::Value = serde_json::from_slice(raw)?;
        let identity = v["__CURSOR"].as_str().context("journal cursor missing")?;
        ensure!(
            !identity.is_empty() && identity.len() <= 4096,
            "invalid journal cursor"
        );
        let line = v["MESSAGE"]
            .as_str()
            .context("journal message is not UTF8 text")?;
        ensure!(line.len() <= MAX_LINE, "oversize journal message");
        let at = v["__REALTIME_TIMESTAMP"]
            .as_str()
            .context("journal timestamp missing")?
            .parse::<i64>()?
            / 1_000_000;
        ensure!(at >= 0 && at <= now + 5, "invalid journal timestamp");
        next = identity.into();
        if !cursor.is_empty() || preview {
            entries.push(Entry {
                identity: format!("journal:{identity}"),
                line: line.into(),
                at,
                journal: true,
            });
        }
        if entries.len() >= 512 {
            complete = false;
            break;
        }
    }
    // Empty journal is a visible unavailability state, not a healthy empty source.
    ensure!(
        !cursor.is_empty() || !next.is_empty(),
        "no readable entries for this unit; verify unit and journal permissions"
    );
    Ok(Batch {
        entries,
        cursor: next,
        complete,
    })
}
pub async fn preview(
    config: einblick_core::config::ServiceLogConfig,
    source: LogSource,
) -> Result<Vec<String>> {
    match source.input {
        SourceInput::File { path } => {
            tokio::task::spawn_blocking(move || {
                let mut file = open_log(&config, &path)?;
                let len = file.metadata()?.len();
                let start = len.saturating_sub(128 * 1024);
                file.seek(SeekFrom::Start(start))?;
                let mut bytes = vec![];
                file.take(128 * 1024).read_to_end(&mut bytes)?;
                let prefix = if start > 0 {
                    bytes
                        .iter()
                        .position(|b| *b == b'\n')
                        .map_or(bytes.len(), |p| p + 1)
                } else {
                    0
                };
                let text =
                    std::str::from_utf8(&bytes[prefix..]).context("log preview is not UTF8")?;
                let mut lines = text
                    .lines()
                    .filter(|l| l.len() <= MAX_LINE)
                    .map(str::to_owned)
                    .collect::<Vec<_>>();
                if lines.len() > 100 {
                    lines.drain(..lines.len() - 100);
                }
                Ok(lines)
            })
            .await?
        }
        SourceInput::Journal { unit } => Ok(journal(&config, &unit, "", unix_now(), true)
            .await?
            .entries
            .into_iter()
            .map(|e| e.line)
            .collect()),
    }
}
struct Runtime {
    revision: i64,
    engine: PolicyEngine,
    ready_at: i64,
    readers: HashMap<String, FileReader>,
    states: HashMap<String, SourceState>,
    filters: HashMap<String, Vec<CompiledFilter>>,
    failed: bool,
    last_poll: i64,
    warmed: bool,
}
async fn mark_incomplete(
    rt: &mut Runtime,
    db: &Database,
    service: &ProtectedService,
    now: i64,
    window: i64,
    message: &str,
) {
    rt.engine.clear();
    rt.ready_at = now + window;
    rt.failed = true;
    rt.warmed = false;
    for source in service.sources.iter().filter(|s| s.enabled) {
        let mut state = rt.states.get(&source.id).cloned().unwrap_or_default();
        state.status = "incomplete".into();
        state.error = Some(message.into());
        state.updated = now;
        state.revision = service.revision;
        if let Err(e) = db
            .service_checkpoint(service.clone(), source.clone(), state.clone(), vec![])
            .await
        {
            tracing::warn!(%e,"source evidence gap could not be persisted");
        }
        rt.states.insert(source.id.clone(), state);
    }
}

pub async fn run(
    config: Config,
    db: Database,
    commands: mpsc::Sender<Command>,
    mut stop: broadcast::Receiver<()>,
) {
    let mut runtimes: HashMap<i64, Runtime> = HashMap::new();
    let mut last_prune = 0;
    let mut interval = tokio::time::interval(Duration::from_secs(2));
    interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    loop {
        tokio::select! {_=stop.recv()=>break,_=interval.tick()=>{}}
        if unix_now() - last_prune >= 60 {
            if let Err(e) = db
                .prune_service_history(unix_now(), config.retention.event_days)
                .await
            {
                tracing::warn!(%e,"service retention failed; clearing evidence");
                runtimes.clear();
                continue;
            }
            last_prune = unix_now();
        }
        let services = match db.services().await {
            Ok(s) => s,
            Err(e) => {
                tracing::warn!(%e,"service configuration unavailable; clearing evidence");
                runtimes.clear();
                continue;
            }
        };
        runtimes.retain(|id, _| services.iter().any(|s| s.id == *id && s.enabled));
        for service in services.into_iter().filter(|s| s.enabled) {
            let now = unix_now();
            let window = service
                .policies
                .iter()
                .filter(|p| p.enabled)
                .map(|p| p.window_seconds)
                .max()
                .unwrap_or(1);
            let rt = runtimes.entry(service.id).or_insert_with(|| Runtime {
                revision: service.revision,
                engine: PolicyEngine::default(),
                ready_at: now + window,
                readers: HashMap::new(),
                states: HashMap::new(),
                filters: HashMap::new(),
                failed: false,
                last_poll: now,
                warmed: false,
            });
            if rt.revision != service.revision {
                rt.revision = service.revision;
                rt.engine.clear();
                rt.ready_at = now + window;
                rt.readers.clear();
                rt.states.clear();
                rt.filters.clear();
                rt.warmed = false;
            }
            if now < rt.last_poll || now - rt.last_poll > 5 {
                mark_incomplete(
                    rt,
                    &db,
                    &service,
                    now,
                    window,
                    "Collection interval or system clock changed; rebuilding evidence",
                )
                .await;
            }
            rt.last_poll = now;
            if now >= rt.ready_at && !rt.warmed {
                // Warm-up hits must not carry a ban-duration cooldown into
                // trusted live evaluation. Start fresh after a complete window.
                rt.engine.clear();
                rt.warmed = true;
            }
            let mut pending = vec![];
            let mut failed = false;
            for source in service.sources.iter().filter(|s| s.enabled) {
                let outcome = async {
                    if !rt.states.contains_key(&source.id) {
                        rt.states.insert(
                            source.id.clone(),
                            db.source_state(service.id, source).await?,
                        );
                    }
                    let mut state = rt.states[&source.id].clone();
                    let batch = match &source.input {
                        SourceInput::File { path } => {
                            let mut reader = rt.readers.remove(&source.id).unwrap_or_default();
                            let cfg = config.service_logs.clone();
                            let path = path.clone();
                            let cursor = state.cursor.clone();
                            let (reader, result) = tokio::task::spawn_blocking(move || {
                                let result = reader.read(&cfg, &path, &cursor, now);
                                (reader, result)
                            })
                            .await?;
                            rt.readers.insert(source.id.clone(), reader);
                            result?
                        }
                        SourceInput::Journal { unit } => {
                            journal(&config.service_logs, unit, &state.cursor, now, false).await?
                        }
                    };
                    if !rt.filters.contains_key(&source.id) {
                        rt.filters.insert(
                            source.id.clone(),
                            source
                                .filters
                                .iter()
                                .map(CompiledFilter::new)
                                .collect::<Result<Vec<_>>>()?,
                        );
                    }
                    let filters = &rt.filters[&source.id];
                    let mut events = vec![];
                    let mut extraction_failed = false;
                    for entry in &batch.entries {
                        for filter in filters {
                            let result =
                                filter.parse(service.id, &source.id, &entry.line, 0, entry.at);
                            if result.error.is_some() {
                                extraction_failed = true;
                            }
                            if let Some(mut e) = result.event {
                                e.observed_at = now;
                                if entry.journal && e.timestamp_origin == "observation" {
                                    e.timestamp_origin = "journal".into();
                                }
                                if e.at>now+5 {extraction_failed=true;continue;}
                                if e.at<now-window {extraction_failed=true;}
                                let key =
                                    format!("{}:{}:{}", entry.identity, e.event_type, e.source_ip);
                                events.push((key, e));
                            }
                        }
                    }
                    state.revision = service.revision;
                    state.cursor = batch.cursor;
                    state.updated = now;
                    state.entries += batch.entries.len() as u64;
                    let complete = batch.complete && !extraction_failed;
                    state.status = if !complete {
                        "incomplete"
                    } else if now < rt.ready_at {
                        "warming"
                    } else {
                        "healthy"
                    }
                    .into();
                    state.error = if complete {
                        None
                    } else {
                        Some(
                            "Backlog, rotation gap, timestamp, or extraction error; policy evidence reset"
                                .into(),
                        )
                    };
                    let new = db
                        .service_checkpoint(service.clone(), source.clone(), state.clone(), events)
                        .await?;
                    rt.states.insert(source.id.clone(), state);
                    Ok::<_, anyhow::Error>((new, complete))
                }
                .await;
                match outcome {
                    Ok((events, complete)) => {
                        pending.extend(events);
                        failed |= !complete;
                    }
                    Err(e) => {
                        failed = true;
                        let mut state = rt.states.get(&source.id).cloned().unwrap_or_default();
                        state.status = "unavailable".into();
                        state.error = Some(e.to_string());
                        state.updated = now;
                        if let Err(error) = db
                            .service_checkpoint(
                                service.clone(),
                                source.clone(),
                                state.clone(),
                                vec![],
                            )
                            .await
                        {
                            tracing::warn!(%error,"source failure could not be persisted");
                        }
                        rt.states.insert(source.id.clone(), state);
                    }
                }
            }
            if unix_now() - now > 5 {
                mark_incomplete(
                    rt,
                    &db,
                    &service,
                    now,
                    window,
                    "Collection batch exceeded five seconds; evidence incomplete",
                )
                .await;
                failed = true;
            }
            if failed {
                rt.engine.clear();
                rt.ready_at = now + window;
                rt.failed = true;
                rt.warmed = false;
                continue;
            }
            if rt.failed {
                rt.engine.clear();
                rt.ready_at = now + window;
                rt.failed = false;
                rt.warmed = false;
            }
            pending.sort_by_key(|e| e.at);
            for event in pending {
                match rt.engine.evaluate(&service, &event) {
                    Ok(hits) => {
                        for hit in hits {
                            let (reply, rx) = oneshot::channel();
                            let command = Command {
                                action: Action::ServiceDecision {
                                    hit: Box::new(hit),
                                    complete: rt.warmed && now >= rt.ready_at,
                                },
                                reply,
                            };
                            if commands.try_send(command).is_err() {
                                mark_incomplete(
                                    rt,
                                    &db,
                                    &service,
                                    now,
                                    window,
                                    "Enforcement command queue unavailable; rebuilding evidence",
                                )
                                .await;
                                break;
                            }
                            if !matches!(rx.await, Ok(Ok(()))) {
                                mark_incomplete(
                                    rt,
                                    &db,
                                    &service,
                                    now,
                                    window,
                                    "Decision failed or configuration changed; rebuilding evidence",
                                )
                                .await;
                                break;
                            }
                        }
                    }
                    Err(e) => {
                        tracing::warn!(%e,service=service.id,"service evidence incomplete");
                        mark_incomplete(rt, &db, &service, now, window, &e.to_string()).await;
                        break;
                    }
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn file_cursor_restart_rotation_truncation_and_sandbox() {
        let dir = std::env::temp_dir().join(format!("einblick-logs-{}", rand::random::<u64>()));
        std::fs::create_dir(&dir).unwrap();
        let path = dir.join("auth.log");
        std::fs::write(&path, "old\n").unwrap();
        let config = einblick_core::config::ServiceLogConfig {
            allowed_roots: vec![dir.to_str().unwrap().into()],
            journal_directory: String::new(),
        };
        let mut reader = FileReader::default();
        let b = reader
            .read(&config, path.to_str().unwrap(), "", 100)
            .unwrap();
        assert!(b.entries.is_empty());
        use std::io::Write;
        let mut f = std::fs::OpenOptions::new()
            .append(true)
            .open(&path)
            .unwrap();
        writeln!(f, "failure").unwrap();
        let b = reader
            .read(&config, path.to_str().unwrap(), &b.cursor, 101)
            .unwrap();
        assert_eq!(b.entries[0].line, "failure");
        let mut restarted = FileReader::default();
        let b = restarted
            .read(&config, path.to_str().unwrap(), &b.cursor, 102)
            .unwrap();
        assert!(b.entries.is_empty());
        std::fs::rename(&path, dir.join("auth.log.1")).unwrap();
        std::fs::write(&path, "rotated\n").unwrap();
        let b = reader
            .read(&config, path.to_str().unwrap(), &b.cursor, 103)
            .unwrap();
        assert_eq!(b.entries[0].line, "rotated");
        std::fs::write(&path, "x\n").unwrap();
        let b = reader
            .read(&config, path.to_str().unwrap(), &b.cursor, 104)
            .unwrap();
        assert!(!b.complete);
        assert_eq!(b.entries[0].line, "x");
        std::os::unix::fs::symlink("/etc/passwd", dir.join("link")).unwrap();
        assert!(open_log(&config, dir.join("link").to_str().unwrap()).is_err());
        assert!(open_log(&config, "/etc/passwd").is_err());
        std::fs::remove_dir_all(dir).unwrap();
    }
    #[test]
    fn journal_timestamp_cursor_attribution_and_invalid_evidence() {
        let entry = serde_json::json!({"MESSAGE":"Failed password for root from 192.0.2.1 port 44","__CURSOR":"s=1;i=2","__REALTIME_TIMESTAMP":"100000000"});
        let data = entry.to_string();
        let baseline = decode_journal(data.as_bytes(), "", 101, false).unwrap();
        assert!(baseline.entries.is_empty());
        assert_eq!(baseline.cursor, "s=1;i=2");
        let resumed = decode_journal(data.as_bytes(), "s=1;i=1", 101, false).unwrap();
        assert_eq!(resumed.entries[0].at, 100);
        assert!(resumed.entries[0].journal);
        assert!(resumed.complete);
        assert!(decode_journal(b"{}", "old", 101, false).is_err());
        assert!(decode_journal(b"", "", 101, false).is_err());
        let mut invalid = entry.clone();
        invalid["MESSAGE"] = serde_json::json!([255, 254]);
        assert!(decode_journal(invalid.to_string().as_bytes(), "old", 101, false).is_err());
        invalid = entry;
        invalid["__REALTIME_TIMESTAMP"] = serde_json::json!("999000000");
        assert!(decode_journal(invalid.to_string().as_bytes(), "old", 101, false).is_err());
    }
    #[tokio::test]
    async fn journal_backlog_advances_a_bounded_cursor_batch() {
        let path = std::env::temp_dir().join(format!(
            "einblick-journal-fixture-{}",
            rand::random::<u64>()
        ));
        let input=(0..1025).map(|i|serde_json::json!({"MESSAGE":"authentication failure","__CURSOR":format!("cursor-{i}"),"__REALTIME_TIMESTAMP":"100000000"}).to_string()).collect::<Vec<_>>().join("\n");
        std::fs::write(&path, input).unwrap();
        let child = tokio::process::Command::new("cat")
            .arg(&path)
            .stdout(std::process::Stdio::piped())
            .kill_on_drop(true)
            .spawn()
            .unwrap();
        let batch = read_journal_child(child, "previous", 101, false)
            .await
            .unwrap();
        assert_eq!(batch.entries.len(), 512);
        assert_eq!(batch.cursor, "cursor-511");
        assert!(!batch.complete);
        std::fs::remove_file(path).unwrap();
    }
}
