//! Periodic, bounded Caddy JSON access-log ingestion, off the packet polling path.
use anyhow::{Context, Result, ensure};
use einblick_core::{Config, caddy::CaddyRequest, storage::Database, unix_now};
use serde::{Deserialize, Serialize};
use std::{
    fs::File,
    io::{Read, Seek, SeekFrom},
    net::IpAddr,
    os::unix::fs::MetadataExt,
    time::Duration,
};
use tokio::sync::broadcast;

const BATCH_BYTES: usize = 256 * 1024;
const MAX_LINE: usize = 64 * 1024;

#[derive(Default, Serialize, Deserialize)]
struct Position {
    dev: u64,
    inode: u64,
    offset: u64,
    generation: u64,
    anchor: String,
    skipping: bool,
}
#[derive(Default)]
struct Reader {
    file: Option<File>,
}
struct Batch {
    cursor: String,
    rows: Vec<(String, CaddyRequest)>,
    skipped: u64,
    gap: bool,
    backlog: bool,
}

fn text(value: &serde_json::Value, max: usize) -> Result<String> {
    let value = value.as_str().context("missing text field")?;
    ensure!(
        !value.is_empty() && value.len() <= max && !value.chars().any(char::is_control),
        "invalid text field"
    );
    Ok(value.into())
}

fn parse(line: &[u8], log_path: &str, now: i64) -> Result<CaddyRequest> {
    let v: serde_json::Value = serde_json::from_slice(line)?;
    // Ignore runtime/debug records, even if they happen to contain request data.
    let logger = v["logger"].as_str().context("missing access logger")?;
    ensure!(
        logger == "http.log.access" || logger.starts_with("http.log.access."),
        "not an access record"
    );
    let at = if let Some(ts) = v["ts"].as_f64() {
        ensure!(
            ts.is_finite() && ts >= 0.0 && ts <= (now + 5) as f64,
            "invalid timestamp"
        );
        ts.floor() as i64
    } else {
        chrono::DateTime::parse_from_rfc3339(v["ts"].as_str().context("missing timestamp")?)?
            .timestamp()
    };
    ensure!(at >= 0 && at <= now + 5, "invalid timestamp");
    let r = &v["request"];
    let remote_ip = r["remote_ip"]
        .as_str()
        .context("missing remote IP")?
        .parse::<IpAddr>()?
        .to_canonical();
    let client_ip = r["client_ip"]
        .as_str()
        .filter(|s| !s.is_empty())
        .map(|s| s.parse::<IpAddr>().map(|ip| ip.to_canonical()))
        .transpose()?;
    let host = text(&r["host"], 255)?;
    let uri = r["uri"].as_str().context("missing URI")?;
    // Store the path only: query strings frequently contain credentials/tokens.
    let path = uri.split(['?', '#']).next().unwrap_or("");
    ensure!(
        (path.starts_with('/') || path == "*") && !path.chars().any(char::is_control),
        "invalid request path"
    );
    ensure!(path.len() <= 2048, "request path exceeds 2048 bytes");
    let method = text(&r["method"], 32)?;
    ensure!(
        method.bytes().all(|b| b.is_ascii_uppercase() || b == b'-'),
        "invalid method"
    );
    let status = v["status"].as_u64().context("missing status")?;
    ensure!(
        (100..=599).contains(&status) || status == 0,
        "invalid HTTP status"
    );
    Ok(CaddyRequest {
        id: 0,
        at,
        remote_ip,
        client_ip,
        host,
        path: path.into(),
        method,
        status: status as u16,
        log_path: log_path.into(),
    })
}

fn anchor(file: &mut File, offset: u64) -> Result<String> {
    let start = offset.saturating_sub(32);
    file.seek(SeekFrom::Start(start))?;
    let mut bytes = vec![0; (offset - start) as usize];
    file.read_exact(&mut bytes)?;
    Ok(hex::encode(bytes))
}

impl Reader {
    fn read(
        &mut self,
        config: &einblick_core::config::ServiceLogConfig,
        path: &str,
        cursor: &str,
        now: i64,
    ) -> Result<Batch> {
        let current = crate::service_logs::open_log(config, path)?;
        let meta = current.metadata()?;
        let mut p: Position = if cursor.is_empty() {
            Position::default()
        } else {
            serde_json::from_str(cursor).context("invalid Caddy file cursor")?
        };
        let mut gap = false;
        let changed = p.inode != 0 && (p.dev != meta.dev() || p.inode != meta.ino());
        let pinned_matches = self
            .file
            .as_ref()
            .and_then(|f| f.metadata().ok())
            .is_some_and(|m| m.dev() == p.dev && m.ino() == p.inode);
        if p.inode == 0
            || (changed
                && (!pinned_matches || self.file.as_ref().unwrap().metadata()?.len() <= p.offset))
        {
            gap = changed && !pinned_matches;
            p = Position {
                dev: meta.dev(),
                inode: meta.ino(),
                ..Default::default()
            };
            self.file = Some(current);
        } else if !changed {
            self.file = Some(current);
        }
        let file = self
            .file
            .as_mut()
            .context("Caddy file descriptor unavailable")?;
        let len = file.metadata()?.len();
        if len < p.offset || (!p.anchor.is_empty() && anchor(file, p.offset)? != p.anchor) {
            p.offset = 0;
            p.generation += 1;
            p.skipping = false;
            gap = true;
        }
        file.seek(SeekFrom::Start(p.offset))?;
        let mut bytes = vec![];
        file.take(BATCH_BYTES as u64).read_to_end(&mut bytes)?;
        let mut rows = vec![];
        let mut skipped = 0;
        let mut start = 0;
        let mut lines = 0;
        for (i, b) in bytes.iter().enumerate() {
            if *b != b'\n' {
                continue;
            }
            if p.skipping {
                p.skipping = false;
            } else if i - start > MAX_LINE {
                skipped += 1;
            } else {
                match parse(&bytes[start..i], path, now) {
                    Ok(row) => rows.push((
                        format!(
                            "{}:{}:{}:{}",
                            p.dev,
                            p.inode,
                            p.generation,
                            p.offset + start as u64
                        ),
                        row,
                    )),
                    Err(_) => skipped += 1,
                }
            }
            start = i + 1;
            lines += 1;
            if lines >= 512 {
                break;
            }
        }
        if lines < 512 && bytes.len() - start > MAX_LINE {
            if !p.skipping {
                skipped += 1;
            }
            p.skipping = true;
            start = bytes.len();
        }
        // Discard an unfinished tail only after the rotated descriptor is drained.
        if changed
            && p.inode != meta.ino()
            && bytes.len() < BATCH_BYTES
            && lines < 512
            && start < bytes.len()
        {
            start = bytes.len();
            skipped += 1;
            gap = true;
        }
        p.offset += start as u64;
        p.anchor = anchor(file, p.offset)?;
        let backlog = len > p.offset && (bytes.len() == BATCH_BYTES || lines >= 512);
        Ok(Batch {
            cursor: serde_json::to_string(&p)?,
            rows,
            skipped,
            gap,
            backlog,
        })
    }
}

pub async fn run(config: Config, db: Database, mut stop: broadcast::Receiver<()>) {
    let mut readers = (0..config.caddy.log_paths.len())
        .map(|_| Reader::default())
        .collect::<Vec<_>>();
    let mut interval = tokio::time::interval(Duration::from_secs(config.caddy.poll_seconds));
    interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    loop {
        tokio::select! { _=stop.recv()=>break, _=interval.tick()=>{} }
        let now = unix_now();
        if config.caddy.enabled {
            for (index, path) in config.caddy.log_paths.iter().enumerate() {
                let mut source = match db.caddy_source(path.clone()).await {
                    Ok(s) => s,
                    Err(e) => {
                        tracing::warn!(%e,"Caddy cursor unavailable");
                        continue;
                    }
                };
                // File operations run on the blocking pool, with bounded reads.
                let mut reader = std::mem::take(&mut readers[index]);
                let log_config = config.service_logs.clone();
                let log_path = path.clone();
                let cursor = source.cursor.clone();
                let result = tokio::task::spawn_blocking(move || {
                    let result = reader.read(&log_config, &log_path, &cursor, now);
                    (reader, result)
                })
                .await;
                let result = match result {
                    Ok((reader, result)) => {
                        readers[index] = reader;
                        result
                    }
                    Err(e) => Err(e.into()),
                };
                source.last_poll = now;
                let rows = match result {
                    Ok(batch) => {
                        source.cursor = batch.cursor;
                        source.last_success = Some(now);
                        source.skipped = source.skipped.saturating_add(batch.skipped as i64);
                        source.gaps = source.gaps.saturating_add(i64::from(batch.gap));
                        source.error = if batch.backlog {
                            Some("Log backlog; continuing next poll".into())
                        } else {
                            None
                        };
                        batch.rows
                    }
                    Err(e) => {
                        source.error = Some(format!("{e:#}"));
                        vec![]
                    }
                };
                if let Err(e) = db.save_caddy_batch(source, rows).await {
                    tracing::warn!(%e,"Caddy evidence could not be saved");
                }
            }
        }
        if let Err(e) = db.prune_caddy(now, config.caddy.clone()).await {
            tracing::warn!(%e,"Caddy retention failed");
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    fn line(ip: &str, uri: &str) -> String {
        serde_json::json!({"logger":"http.log.access.site","ts":100.75,"request":{"remote_ip":ip,"client_ip":"198.51.100.2","host":"example.com:443","uri":uri,"method":"GET","headers":{"Cookie":["secret"]}},"status":200}).to_string()
    }
    #[test]
    fn parses_caddy_fields_without_query_headers_or_proxy_reassignment() {
        let r = parse(
            line("::ffff:192.0.2.1", "/hello?q=secret#fragment").as_bytes(),
            "/logs/access.json",
            101,
        )
        .unwrap();
        assert_eq!(r.at, 100);
        assert_eq!(r.remote_ip.to_string(), "192.0.2.1");
        assert_eq!(r.path, "/hello");
        assert_eq!(r.host, "example.com:443");
        assert!(!serde_json::to_string(&r).unwrap().contains("secret"));
        assert!(parse(line("not-ip", "/").as_bytes(), "p", 101).is_err());
        assert!(parse(line("::1", "/").as_bytes(), "p", 90).is_err());
        let mut v: serde_json::Value = serde_json::from_str(&line("::1", "/")).unwrap();
        v["ts"] = serde_json::json!("1970-01-01T00:01:40Z");
        assert_eq!(parse(v.to_string().as_bytes(), "p", 101).unwrap().at, 100);
        v["logger"] = serde_json::json!("http.log.error");
        assert!(parse(v.to_string().as_bytes(), "p", 101).is_err());
    }
    #[test]
    fn file_backfill_partial_restart_rotation_truncation_and_invalid_lines() {
        let dir = std::env::temp_dir().join(format!("einblick-caddy-{}", rand::random::<u64>()));
        std::fs::create_dir(&dir).unwrap();
        let path = dir.join("access.json");
        let path = path.to_str().unwrap();
        let config = einblick_core::config::ServiceLogConfig {
            allowed_roots: vec![dir.to_str().unwrap().into()],
            journal_directory: String::new(),
        };
        let valid = line("2001:db8::1", "/first");
        std::fs::write(path, format!("{valid}\n{{partial")).unwrap();
        let mut reader = Reader::default();
        let b = reader.read(&config, path, "", 101).unwrap();
        assert_eq!(b.rows.len(), 1);
        let b = Reader::default()
            .read(&config, path, &b.cursor, 102)
            .unwrap();
        assert!(b.rows.is_empty());
        let mut old = std::fs::OpenOptions::new().append(true).open(path).unwrap();
        writeln!(
            old,
            "\nnot json\n{}\n{}",
            "x".repeat(MAX_LINE + 1),
            line("192.0.2.1", "/second")
        )
        .unwrap();
        let b = reader.read(&config, path, &b.cursor, 103).unwrap();
        assert_eq!(b.rows.len(), 1);
        assert_eq!(b.skipped, 3);
        std::fs::rename(path, dir.join("access.json.1")).unwrap();
        std::fs::write(path, format!("{valid}\n")).unwrap();
        writeln!(old, "{}", line("192.0.2.1", "/late")).unwrap();
        let b = reader.read(&config, path, &b.cursor, 104).unwrap();
        assert_eq!(b.rows[0].1.path, "/late");
        let b = reader.read(&config, path, &b.cursor, 105).unwrap();
        assert_eq!(b.rows[0].1.path, "/first");
        std::fs::write(path, format!("{}\n", line("::1", "/short"))).unwrap();
        let b = reader.read(&config, path, &b.cursor, 106).unwrap();
        assert!(b.gap);
        assert_eq!(b.rows[0].1.path, "/short");
        assert!(reader.read(&config, "/etc/passwd", "", 106).is_err());
        std::fs::remove_dir_all(dir).unwrap();
    }
}
