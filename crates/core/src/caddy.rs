//! Caddy access-log evidence is independent of packet counters and socket candidates.
use crate::{config::CaddyConfig, storage::Database};
use anyhow::{Result, ensure};
use rusqlite::{OptionalExtension, params};
use serde::{Deserialize, Serialize};
use std::net::IpAddr;

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct CaddyRequest {
    pub id: i64,
    pub at: i64,
    pub remote_ip: IpAddr,
    pub client_ip: Option<IpAddr>,
    pub host: String,
    pub path: String,
    pub method: String,
    pub status: u16,
    pub log_path: String,
}

#[derive(Clone, Default, Serialize, Deserialize)]
pub struct CaddySource {
    pub log_path: String,
    #[serde(skip)]
    pub cursor: String,
    pub last_poll: i64,
    pub last_success: Option<i64>,
    pub skipped: i64,
    pub gaps: i64,
    pub error: Option<String>,
}

#[derive(Serialize)]
pub struct CaddyPage {
    pub application: &'static str,
    pub attribution: &'static str,
    pub enabled: bool,
    pub poll_seconds: u64,
    pub retention_days: i64,
    pub sources: Vec<CaddySource>,
    pub rows: Vec<CaddyRequest>,
    pub next_cursor: Option<String>,
}

impl Database {
    pub async fn caddy_source(&self, path: String) -> Result<CaddySource> {
        self.read(move |c| {
            Ok(c.query_row("SELECT cursor,last_poll,last_success,skipped,gaps,error FROM caddy_sources WHERE log_path=?", [&path], |r| {
                Ok(CaddySource { log_path: path.clone(), cursor:r.get(0)?, last_poll:r.get(1)?, last_success:r.get(2)?, skipped:r.get(3)?, gaps:r.get(4)?, error:r.get(5)? })
            }).optional()?.unwrap_or(CaddySource { log_path:path, ..Default::default() }))
        }).await
    }

    /// Commit evidence and its cursor together so a crash cannot replay requests.
    pub async fn save_caddy_batch(
        &self,
        source: CaddySource,
        requests: Vec<(String, CaddyRequest)>,
    ) -> Result<()> {
        self.call(move |c| {
            let t = c.transaction()?;
            for (identity, r) in requests {
                t.execute("INSERT OR IGNORE INTO caddy_requests(log_path,identity,at,remote_ip,client_ip,host,path,method,status) VALUES(?,?,?,?,?,?,?,?,?)",
                    params![source.log_path,identity,r.at,r.remote_ip.to_string(),r.client_ip.map(|ip|ip.to_string()),r.host,r.path,r.method,r.status])?;
            }
            t.execute("INSERT INTO caddy_sources VALUES(?,?,?,?,?,?,?) ON CONFLICT(log_path) DO UPDATE SET cursor=excluded.cursor,last_poll=excluded.last_poll,last_success=excluded.last_success,skipped=excluded.skipped,gaps=excluded.gaps,error=excluded.error",
                params![source.log_path,source.cursor,source.last_poll,source.last_success,source.skipped,source.gaps,source.error])?;
            t.commit()?;
            Ok(())
        }).await
    }

    pub async fn prune_caddy(&self, now: i64, config: CaddyConfig) -> Result<()> {
        self.call(move |c| {
            let t = c.transaction()?;
            t.execute("DELETE FROM caddy_requests WHERE at < ?", [now-config.retention_days*86400])?;
            let count:i64 = t.query_row("SELECT count(*) FROM caddy_requests", [], |r|r.get(0))?;
            let excess = count.saturating_sub(config.row_limit as i64);
            if excess > 0 {
                t.execute("DELETE FROM caddy_requests WHERE id IN (SELECT id FROM caddy_requests ORDER BY at,id LIMIT ?)", [excess])?;
            }
            t.commit()?;
            Ok(())
        }).await
    }

    pub async fn caddy_requests(
        &self,
        ip: IpAddr,
        from: i64,
        to: i64,
        before: Option<(i64, i64)>,
        limit: usize,
    ) -> Result<(Vec<CaddyRequest>, Option<String>)> {
        ensure!(
            from >= 0 && to >= from && to - from <= 90 * 86400,
            "Caddy range must be between zero and 90 days"
        );
        ensure!(
            (1..=200).contains(&limit),
            "limit must be between 1 and 200"
        );
        ensure!(
            before.is_none_or(|(at, id)| at >= 0 && id > 0),
            "invalid Caddy cursor"
        );
        self.read(move |c| {
            let (at,id) = before.unwrap_or((i64::MAX,i64::MAX));
            let mut s = c.prepare("SELECT id,at,remote_ip,client_ip,host,path,method,status,log_path FROM caddy_requests WHERE remote_ip=? AND at>=? AND at<=? AND (at,id)<(?,?) ORDER BY at DESC,id DESC LIMIT ?")?;
            let mut rows = s.query(params![ip.to_string(),from,to,at,id,(limit+1) as i64])?;
            let mut out = vec![];
            while let Some(r) = rows.next()? {
                out.push(CaddyRequest {id:r.get(0)?,at:r.get(1)?,remote_ip:r.get::<_,String>(2)?.parse()?,client_ip:r.get::<_,Option<String>>(3)?.map(|s|s.parse()).transpose()?,host:r.get(4)?,path:r.get(5)?,method:r.get(6)?,status:r.get(7)?,log_path:r.get(8)?});
            }
            let more = out.len() > limit;
            out.truncate(limit);
            let cursor = if more {out.last().map(|r|serde_json::to_string(&(r.at,r.id))).transpose()?} else {None};
            Ok((out,cursor))
        }).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn version_five_backup_preserves_existing_data_and_reopens() {
        let dir = std::env::temp_dir().join(format!(
            "einblick-caddy-v5-{}",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir(&dir).unwrap();
        let path = dir.join("history.sqlite");
        let path = path.to_str().unwrap();
        let db = Database::open(path).unwrap();
        db.call(|c|{c.execute_batch("DROP TABLE caddy_requests;DROP TABLE caddy_sources;INSERT INTO settings VALUES('migration_test','preserved');PRAGMA user_version=5;")?;Ok(())}).await.unwrap();
        drop(db);
        let db = Database::open(path).unwrap();
        db.call(|c| {
            assert_eq!(
                c.pragma_query_value(None, "user_version", |r| r.get::<_, i64>(0))?,
                6
            );
            assert_eq!(
                c.query_row(
                    "SELECT value FROM settings WHERE key='migration_test'",
                    [],
                    |r| r.get::<_, String>(0)
                )?,
                "preserved"
            );
            Ok(())
        })
        .await
        .unwrap();
        let backup = rusqlite::Connection::open(format!("{path}.schema-v5-backup")).unwrap();
        assert_eq!(
            backup
                .pragma_query_value(None, "user_version", |r| r.get::<_, i64>(0))
                .unwrap(),
            5
        );
        drop(backup);
        drop(db);
        let reopened = Database::open(path).unwrap();
        assert!(
            reopened
                .caddy_requests("192.0.2.1".parse().unwrap(), 0, 100, None, 100)
                .await
                .unwrap()
                .0
                .is_empty()
        );
        drop(reopened);
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[tokio::test]
    async fn evidence_cursor_paging_ip_isolation_and_retention() {
        let db = Database::open(":memory:").unwrap();
        let source = CaddySource {
            log_path: "/logs/caddy.json".into(),
            cursor: "saved-position".into(),
            last_poll: 100,
            last_success: Some(100),
            ..Default::default()
        };
        let row = CaddyRequest {
            id: 0,
            at: 100,
            remote_ip: "192.0.2.1".parse().unwrap(),
            client_ip: Some("198.51.100.1".parse().unwrap()),
            host: "example.com".into(),
            path: "/hello".into(),
            method: "GET".into(),
            status: 200,
            log_path: source.log_path.clone(),
        };
        let mut other = row.clone();
        other.remote_ip = "2001:db8::1".parse().unwrap();
        let batch = vec![
            ("a".into(), row.clone()),
            ("b".into(), row.clone()),
            ("c".into(), other),
        ];
        db.save_caddy_batch(source.clone(), batch.clone())
            .await
            .unwrap();
        db.save_caddy_batch(source.clone(), batch).await.unwrap();
        assert_eq!(
            db.caddy_source(source.log_path).await.unwrap().cursor,
            "saved-position"
        );
        let (first, cursor) = db
            .caddy_requests(row.remote_ip, 0, 101, None, 1)
            .await
            .unwrap();
        assert_eq!(first.len(), 1);
        let (next, end) = db
            .caddy_requests(
                row.remote_ip,
                0,
                101,
                Some(serde_json::from_str(&cursor.unwrap()).unwrap()),
                1,
            )
            .await
            .unwrap();
        assert_eq!(next.len(), 1);
        assert_ne!(first[0].id, next[0].id);
        assert!(end.is_none());
        assert!(
            db.caddy_requests(row.client_ip.unwrap(), 0, 101, None, 100)
                .await
                .unwrap()
                .0
                .is_empty()
        );
        assert!(
            db.caddy_requests(row.remote_ip, 102, 101, None, 100)
                .await
                .is_err()
        );
        let source = CaddySource {
            log_path: row.log_path.clone(),
            ..Default::default()
        };
        let many = (0..130)
            .map(|i| {
                let mut r = row.clone();
                r.at = 101 + i;
                (format!("many-{i}"), r)
            })
            .collect();
        db.save_caddy_batch(source, many).await.unwrap();
        db.prune_caddy(
            200,
            CaddyConfig {
                row_limit: 128,
                ..Default::default()
            },
        )
        .await
        .unwrap();
        let (retained, _) = db
            .caddy_requests(row.remote_ip, 0, 300, None, 200)
            .await
            .unwrap();
        assert_eq!(retained.len(), 128);
        assert_eq!(retained.last().unwrap().at, 103);
        db.prune_caddy(
            87000,
            CaddyConfig {
                retention_days: 1,
                ..Default::default()
            },
        )
        .await
        .unwrap();
        assert!(
            db.caddy_requests(row.remote_ip, 0, 101, None, 100)
                .await
                .unwrap()
                .0
                .is_empty()
        );
    }
}
