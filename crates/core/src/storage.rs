use crate::{Aggregate, Event, Rule, RuleKind, config::Retention};
use anyhow::{Context, Result, anyhow, ensure};
use rusqlite::{Connection, OptionalExtension, params};
use serde_json::Value;
use std::{
    path::Path,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
        mpsc::{SyncSender, sync_channel},
    },
};
use tokio::sync::oneshot;

type Job = Box<dyn FnOnce(&mut Connection) + Send>;
#[derive(Clone)]
pub struct Database {
    tx: SyncSender<Job>,
    read_tx: SyncSender<Job>,
    pub healthy: Arc<AtomicBool>,
}
impl Database {
    pub fn open(path: &str) -> Result<Self> {
        if path != ":memory:"
            && let Some(p) = Path::new(path)
                .parent()
                .filter(|p| !p.as_os_str().is_empty())
        {
            std::fs::create_dir_all(p)?;
        }
        let mut conn = Connection::open(path).context("open SQLite database")?;
        conn.busy_timeout(std::time::Duration::from_secs(2))?;
        conn.execute_batch(
            "PRAGMA journal_mode=WAL; PRAGMA foreign_keys=ON; PRAGMA synchronous=NORMAL;",
        )?;
        let version: i64 = conn.pragma_query_value(None, "user_version", |r| r.get(0))?;
        ensure!(
            version <= 3,
            "database schema is newer than this application"
        );
        if version == 0 {
            let t = conn.transaction()?;
            t.execute_batch("CREATE TABLE rules (id INTEGER PRIMARY KEY AUTOINCREMENT, network TEXT NOT NULL, kind TEXT NOT NULL, reason TEXT NOT NULL, actor TEXT NOT NULL, created INTEGER NOT NULL, expires INTEGER, enabled INTEGER NOT NULL, applied INTEGER NOT NULL DEFAULT 0, error TEXT);
                CREATE TABLE events (id INTEGER PRIMARY KEY AUTOINCREMENT, at INTEGER NOT NULL, kind TEXT NOT NULL, detail TEXT NOT NULL);
                CREATE INDEX events_at ON events(at);
                CREATE TABLE aggregates (resolution TEXT NOT NULL, at INTEGER NOT NULL, data TEXT NOT NULL, PRIMARY KEY(resolution,at));
                CREATE TABLE settings (key TEXT PRIMARY KEY, value TEXT NOT NULL);
                PRAGMA user_version=1;")?;
            t.commit()?;
        }
        if version < 2 {
            if version == 1 && path != ":memory:" {
                let backup_path = format!("{path}.schema-v1-backup");
                ensure!(
                    !Path::new(&backup_path).exists(),
                    "migration backup already exists: {backup_path}; preserve it and choose a new database path before retrying"
                );
                conn.backup(rusqlite::MAIN_DB, &backup_path, None)?;
            }
            let t = conn.transaction()?;
            t.execute_batch(include_str!("traffic_schema.sql"))?;
            t.commit()?;
        }
        if version < 3 {
            if version == 2 && path != ":memory:" {
                let backup_path = format!("{path}.schema-v2-backup");
                ensure!(
                    !Path::new(&backup_path).exists(),
                    "migration backup already exists: {backup_path}; preserve it before retrying"
                );
                conn.backup(rusqlite::MAIN_DB, &backup_path, None)?;
            }
            let t = conn.transaction()?;
            t.execute_batch(include_str!("application_schema.sql"))?;
            t.commit()?;
        }
        let (read_tx, read_rx) = sync_channel::<Job>(16);
        if path != ":memory:" {
            let mut reader =
                Connection::open_with_flags(path, rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY)?;
            reader.busy_timeout(std::time::Duration::from_secs(2))?;
            std::thread::Builder::new()
                .name("sqlite-reader".into())
                .spawn(move || {
                    while let Ok(job) = read_rx.recv() {
                        job(&mut reader);
                    }
                })?;
        }
        let (tx, rx) = sync_channel::<Job>(64);
        std::thread::Builder::new()
            .name("sqlite-writer".into())
            .spawn(move || {
                while let Ok(job) = rx.recv() {
                    job(&mut conn);
                }
            })?;
        Ok(Self {
            read_tx: if path == ":memory:" {
                tx.clone()
            } else {
                read_tx
            },
            tx,
            healthy: Arc::new(AtomicBool::new(true)),
        })
    }
    pub async fn read<T: Send + 'static>(
        &self,
        f: impl FnOnce(&mut Connection) -> Result<T> + Send + 'static,
    ) -> Result<T> {
        let (tx, rx) = oneshot::channel();
        self.read_tx
            .try_send(Box::new(move |c| {
                let _ = tx.send(f(c));
            }))
            .map_err(|_| anyhow!("history read queue full or unavailable"))?;
        rx.await.context("history reader stopped")?
    }
    pub async fn call<T: Send + 'static>(
        &self,
        f: impl FnOnce(&mut Connection) -> Result<T> + Send + 'static,
    ) -> Result<T> {
        let (tx, rx) = oneshot::channel();
        let health = self.healthy.clone();
        self.tx
            .try_send(Box::new(move |c| {
                let result = f(c);
                health.store(result.is_ok(), Ordering::Release);
                let _ = tx.send(result);
            }))
            .map_err(|_| {
                self.healthy.store(false, Ordering::Release);
                anyhow!("storage queue full or unavailable")
            })?;
        rx.await.context("storage worker stopped")?
    }
    pub async fn rules(&self) -> Result<Vec<Rule>> {
        self.call(|c| {
        let mut s=c.prepare("SELECT id,network,kind,reason,actor,created,expires,enabled,applied,error FROM rules WHERE enabled=1 AND (expires IS NULL OR expires>unixepoch()) ORDER BY id")?;
        let mut out=vec![]; let mut rows=s.query([])?;
        while let Some(r)=rows.next()? { out.push(Rule{id:r.get(0)?,network:r.get::<_,String>(1)?.parse()?,kind:if r.get::<_,String>(2)?=="allow" {RuleKind::Allow}else{RuleKind::Block},reason:r.get(3)?,actor:r.get(4)?,created:r.get(5)?,expires:r.get(6)?,enabled:r.get(7)?,applied:r.get(8)?,error:r.get(9)?}); } Ok(out)
    }).await
    }
    pub async fn insert_rule(&self, mut rule: Rule) -> Result<Rule> {
        self.call(move|c| {
        let t=c.transaction()?;
        let count:i64=t.query_row("SELECT count(*) FROM rules WHERE enabled=1 AND (expires IS NULL OR expires>unixepoch())",[],|r|r.get(0))?;
        ensure!(count<1024,"rule capacity reached");
        let kind=if rule.kind==RuleKind::Allow{"allow"}else{"block"};
        t.execute("INSERT INTO rules(network,kind,reason,actor,created,expires,enabled,applied) VALUES(?,?,?,?,?,?,1,0)",params![rule.network.to_string(),kind,rule.reason,rule.actor,rule.created,rule.expires])?;
        rule.id=t.last_insert_rowid();
        t.execute("INSERT INTO events(at,kind,detail) VALUES(?,?,?)",params![rule.created,"rule_created",serde_json::to_string(&rule)?])?;
        t.commit()?; Ok(rule)
    }).await
    }
    pub async fn remove_rule(&self, id: i64, now: i64) -> Result<()> {
        self.call(move |c| {
            let t = c.transaction()?;
            ensure!(
                t.execute(
                    "UPDATE rules SET enabled=0,applied=0 WHERE id=? AND enabled=1",
                    [id]
                )? == 1,
                "active rule not found"
            );
            t.execute(
                "INSERT INTO events(at,kind,detail) VALUES(?,?,?)",
                params![
                    now,
                    "rule_removed",
                    serde_json::json!({"id":id,"actor":"admin"}).to_string()
                ],
            )?;
            t.commit()?;
            Ok(())
        })
        .await
    }
    pub async fn applied(&self, rules: Vec<Rule>) -> Result<()> {
        self.call(move |c| {
            let t = c.transaction()?;
            for r in rules {
                t.execute(
                    "UPDATE rules SET applied=?,error=? WHERE id=?",
                    params![r.applied, r.error, r.id],
                )?;
            }
            t.commit()?;
            Ok(())
        })
        .await
    }
    pub async fn event(&self, at: i64, kind: &str, detail: Value) -> Result<()> {
        let kind = kind.to_owned();
        self.call(move |c| {
            c.execute(
                "INSERT INTO events(at,kind,detail) VALUES(?,?,?)",
                params![at, kind, detail.to_string()],
            )?;
            Ok(())
        })
        .await
    }
    pub async fn events(&self, limit: u32, before: i64) -> Result<Vec<Event>> {
        self.read(move |c| {
            let mut s = c.prepare(
                "SELECT id,at,kind,detail FROM events WHERE id<? ORDER BY id DESC LIMIT ?",
            )?;
            let mut rows = s.query(params![before, limit.min(200)])?;
            let mut out = vec![];
            let mut bytes = 0;
            while let Some(r) = rows.next()? {
                let detail: String = r.get(3)?;
                bytes += detail.len();
                if bytes > 4 * 1024 * 1024 {
                    break;
                }
                out.push(Event {
                    id: r.get(0)?,
                    at: r.get(1)?,
                    kind: r.get(2)?,
                    detail: serde_json::from_str(&detail)?,
                });
            }
            Ok(out)
        })
        .await
    }
    pub async fn settings(&self) -> Result<(bool, bool)> {
        self.call(|c| {
            let get = |key| -> Result<bool> {
                Ok(
                    c.query_row("SELECT value FROM settings WHERE key=?", [key], |r| {
                        r.get::<_, String>(0)
                    })
                    .optional()?
                    .unwrap_or_else(|| "false".into())
                        == "true",
                )
            };
            Ok((get("automatic")?, get("blocking")?))
        })
        .await
    }
    pub async fn set_mode(&self, automatic: bool, blocking: bool, now: i64) -> Result<()> {
        self.call(move|c| {
        let t=c.transaction()?;
        for (key,value) in [("automatic",automatic),("blocking",blocking)] {t.execute("INSERT INTO settings(key,value) VALUES(?,?) ON CONFLICT(key) DO UPDATE SET value=excluded.value",params![key,value.to_string()])?;}
        t.execute("INSERT INTO events(at,kind,detail) VALUES(?,?,?)",params![now,"mode_changed",serde_json::json!({"automatic":automatic,"blocking":blocking,"actor":"admin"}).to_string()])?;
        t.commit()?;Ok(())
    }).await
    }
    pub async fn aggregate(&self, minute: Aggregate, retention: Retention) -> Result<()> {
        self.call(move|c| {
        let t=c.transaction()?;
        let hour=minute.at/3600*3600;
        let old=t.query_row("SELECT data FROM aggregates WHERE resolution='hour' AND at=?",[hour],|r|r.get::<_,String>(0)).optional()?;
        let mut hourly=if let Some(v)=old {serde_json::from_str::<Aggregate>(&v)?}else{Aggregate{at:hour,totals:Default::default(),sources:vec![],ports:vec![],complete:true}};
        hourly.totals.add(&minute.totals);hourly.complete &=minute.complete;
        // Hourly source detail is intentionally approximate, bounded top-N.
        for s in &minute.sources {if let Some(old)=hourly.sources.iter_mut().find(|old|old.ip==s.ip) {old.packets+=s.packets;old.bytes+=s.bytes;old.syns+=s.syns;}else{hourly.sources.push(s.clone());}}
        hourly.sources.sort_by_key(|s|std::cmp::Reverse(s.packets));hourly.sources.truncate(100);
        for p in &minute.ports {if let Some(old)=hourly.ports.iter_mut().find(|old|old.protocol==p.protocol&&old.port==p.port) {old.packets+=p.packets;}else{hourly.ports.push(p.clone());}}
        hourly.ports.sort_by_key(|p|std::cmp::Reverse(p.packets));hourly.ports.truncate(4096);
        let prior=t.query_row("SELECT data FROM aggregates WHERE resolution='minute' AND at=?",[minute.at],|r|r.get::<_,String>(0)).optional()?;
        let mut combined=minute.clone();
        if let Some(prior)=prior {
            let prior:Aggregate=serde_json::from_str(&prior)?;
            combined.totals.add(&prior.totals); combined.complete &=prior.complete;
            for s in prior.sources {if let Some(old)=combined.sources.iter_mut().find(|old|old.ip==s.ip){old.packets+=s.packets;old.bytes+=s.bytes;old.syns+=s.syns;}else{combined.sources.push(s);}}
            combined.sources.sort_by_key(|s|std::cmp::Reverse(s.packets));combined.sources.truncate(100);
            for p in prior.ports {if let Some(old)=combined.ports.iter_mut().find(|old|old.protocol==p.protocol&&old.port==p.port){old.packets+=p.packets;}else{combined.ports.push(p);}}
            combined.ports.sort_by_key(|p|std::cmp::Reverse(p.packets));combined.ports.truncate(4096);
        }
        for (res,agg) in [("minute",combined),("hour",hourly)] { t.execute("INSERT INTO aggregates(resolution,at,data) VALUES(?,?,?) ON CONFLICT(resolution,at) DO UPDATE SET data=excluded.data",params![res,agg.at,serde_json::to_string(&agg)?])?; }
        for (res,days) in [("minute",retention.minute_days),("hour",retention.hourly_days)] {t.execute("DELETE FROM aggregates WHERE resolution=? AND at<?",params![res,minute.at-days*86400])?;}
        t.execute("DELETE FROM events WHERE at<?",[minute.at-retention.event_days*86400])?;
        t.execute("DELETE FROM rules WHERE (enabled=0 OR expires<?) AND created<?",params![minute.at,minute.at-retention.event_days*86400])?;
        t.commit()?;Ok(())
    }).await
    }
    pub async fn history(&self, resolution: String, from: i64, to: i64) -> Result<Vec<Aggregate>> {
        self.read(move|c| {
        ensure!(resolution=="minute"||resolution=="hour","resolution must be minute or hour");
        let mut s=c.prepare("SELECT data FROM aggregates WHERE resolution=? AND at>=? AND at<=? ORDER BY at DESC LIMIT 1000")?;
        let values=s.query_map(params![resolution,from,to],|r|r.get::<_,String>(0))?;
        let mut out=vec![];let mut bytes=0;for v in values {let v=v?;bytes+=v.len();if bytes>4*1024*1024{break;}out.push(serde_json::from_str(&v)?);}out.reverse();Ok(out)
    }).await
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[tokio::test]
    async fn persistence_rules_audit_and_retention() {
        let db = Database::open(":memory:").unwrap();
        let now = crate::unix_now();
        let r = db
            .insert_rule(Rule {
                id: 0,
                network: "2001:db8::/32".parse().unwrap(),
                kind: RuleKind::Block,
                reason: "test".into(),
                actor: "admin".into(),
                created: now,
                expires: Some(now + 600),
                enabled: true,
                applied: false,
                error: None,
            })
            .await
            .unwrap();
        assert_eq!(db.rules().await.unwrap()[0].network, r.network);
        db.remove_rule(r.id, now).await.unwrap();
        assert!(db.rules().await.unwrap().is_empty());
        db.set_mode(true, true, now).await.unwrap();
        assert_eq!(db.settings().await.unwrap(), (true, true));
        for at in [60, now] {
            db.aggregate(
                Aggregate {
                    at,
                    totals: Default::default(),
                    sources: vec![],
                    ports: vec![],
                    complete: true,
                },
                Retention::default(),
            )
            .await
            .unwrap();
        }
        assert_eq!(db.history("minute".into(), 0, now).await.unwrap().len(), 1);
        assert!(
            db.events(100, i64::MAX)
                .await
                .unwrap()
                .iter()
                .any(|e| e.kind == "rule_created")
        );
    }
    #[tokio::test]
    async fn write_failure_reports_health() {
        let db = Database::open(":memory:").unwrap();
        db.call(|c| {
            c.execute_batch("DROP TABLE events")?;
            Ok(())
        })
        .await
        .unwrap();
        assert!(db.event(1, "test", Value::Null).await.is_err());
        assert!(!db.healthy.load(Ordering::Acquire));
    }
    #[tokio::test]
    async fn version_one_migration_preserves_data_and_creates_recoverable_backup() {
        let stamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let path = std::env::temp_dir().join(format!(
            "einblick-migration-{}-{stamp}.sqlite",
            std::process::id()
        ));
        let name = path.to_str().unwrap();
        let conn = Connection::open(&path).unwrap();
        conn.execute_batch("CREATE TABLE settings(key TEXT PRIMARY KEY,value TEXT NOT NULL);INSERT INTO settings VALUES('automatic','true');INSERT INTO settings VALUES('blocking','true');
            CREATE TABLE events(id INTEGER PRIMARY KEY,at INTEGER NOT NULL,kind TEXT NOT NULL,detail TEXT NOT NULL);INSERT INTO events VALUES(1,120,'test','{}');
            CREATE TABLE aggregates(resolution TEXT,at INTEGER,data TEXT,PRIMARY KEY(resolution,at));
            CREATE TABLE rules(id INTEGER PRIMARY KEY,network TEXT,kind TEXT,actor TEXT,reason TEXT,created INTEGER,expires INTEGER,enabled INTEGER,applied INTEGER,error TEXT);
            INSERT INTO rules VALUES(1,'192.0.2.1/32','allow','admin','protected',120,NULL,1,1,NULL);PRAGMA user_version=1;").unwrap();
        drop(conn);
        let db = Database::open(name).unwrap();
        assert_eq!(db.settings().await.unwrap(), (true, true));
        assert_eq!(db.rules().await.unwrap().len(), 1);
        assert_eq!(db.events(100, i64::MAX).await.unwrap().len(), 1);
        let backup = Connection::open(format!("{name}.schema-v1-backup")).unwrap();
        assert_eq!(
            backup
                .pragma_query_value(None, "user_version", |r| r.get::<_, i64>(0))
                .unwrap(),
            1
        );
        drop(backup);
        drop(db);
        for suffix in ["", "-wal", "-shm", ".schema-v1-backup"] {
            let _ = std::fs::remove_file(format!("{name}{suffix}"));
        }
    }
}

#[cfg(test)]
mod restart_tests {
    use super::*;
    #[tokio::test]
    async fn partial_minutes_merge_across_restarts_without_hourly_double_counting() {
        let db = Database::open(":memory:").unwrap();
        let at = crate::unix_now() / 60 * 60;
        let bucket = Aggregate {
            at,
            totals: crate::Totals {
                packets: 12,
                ..Default::default()
            },
            sources: vec![],
            ports: vec![],
            complete: true,
        };
        db.aggregate(bucket.clone(), Retention::default())
            .await
            .unwrap();
        db.aggregate(bucket, Retention::default()).await.unwrap();
        assert_eq!(
            db.history("minute".into(), at, at).await.unwrap()[0]
                .totals
                .packets,
            24
        );
        assert_eq!(
            db.history("hour".into(), at / 3600 * 3600, at)
                .await
                .unwrap()[0]
                .totals
                .packets,
            24
        );
    }
}
