use crate::{Rule, RuleKind, services::*, storage::Database};
use anyhow::{Result, ensure};
use rusqlite::{OptionalExtension, params};
use std::collections::BTreeMap;

impl Database {
    pub async fn services(&self) -> Result<Vec<ProtectedService>> {
        self.read(|c| {
            let mut s = c.prepare(
                "SELECT data FROM protected_services WHERE deleted=0 ORDER BY id LIMIT 64",
            )?;
            let rows = s.query_map([], |r| r.get::<_, String>(0))?;
            rows.map(|r| Ok(serde_json::from_str(&r?)?)).collect()
        })
        .await
    }
    pub async fn service(&self, id: i64) -> Result<ProtectedService> {
        self.read(move |c| {
            let data: String = c.query_row(
                "SELECT data FROM protected_services WHERE id=? AND deleted=0",
                [id],
                |r| r.get(0),
            )?;
            Ok(serde_json::from_str(&data)?)
        })
        .await
    }
    pub async fn save_service(
        &self,
        mut service: ProtectedService,
        create: bool,
        now: i64,
    ) -> Result<ProtectedService> {
        service.validate()?;
        self.call(move |c| {
            let t = c.transaction()?;
            let patterns = |s: &ProtectedService| -> usize {
                s.sources
                    .iter()
                    .flat_map(|s| &s.filters)
                    .map(|f| f.patterns.len())
                    .sum()
            };
            let mut total = patterns(&service);
            let mut source_count = service.sources.len();
            {
                let mut statement =
                    t.prepare("SELECT data FROM protected_services WHERE deleted=0 AND id<>?")?;
                for row in statement.query_map([if create { 0 } else { service.id }], |r| {
                    r.get::<_, String>(0)
                })? {
                    let existing = serde_json::from_str::<ProtectedService>(&row?)?;
                    total += patterns(&existing);
                    source_count += existing.sources.len();
                }
            }
            ensure!(
                source_count <= 64,
                "global source capacity reached (64 sources)"
            );
            ensure!(total <= 256, "global regex capacity reached (256 patterns)");
            if create {
                let count: i64 = t.query_row(
                    "SELECT count(*) FROM protected_services WHERE deleted=0",
                    [],
                    |r| r.get(0),
                )?;
                ensure!(count < 64, "service capacity reached");
                service.revision = 1;
                service.observe_only = true;
                t.execute(
                    "INSERT INTO protected_services(revision,data) VALUES(1,'{}')",
                    [],
                )?;
                service.id = t.last_insert_rowid();
            } else {
                let revision: i64 = t.query_row(
                    "SELECT revision FROM protected_services WHERE id=? AND deleted=0",
                    [service.id],
                    |r| r.get(0),
                )?;
                ensure!(
                    revision == service.revision,
                    "service changed; reload before saving"
                );
                service.revision += 1;
            }
            t.execute(
                "UPDATE protected_services SET revision=?,data=? WHERE id=?",
                params![
                    service.revision,
                    serde_json::to_string(&service)?,
                    service.id
                ],
            )?;
            t.execute(
                "INSERT INTO events(at,kind,detail) VALUES(?,'service_saved',?)",
                params![now, serde_json::to_string(&service)?],
            )?;
            t.commit()?;
            Ok(service)
        })
        .await
    }
    pub async fn delete_service(&self, id: i64, now: i64) -> Result<()> {
        self.call(move|c|{let t=c.transaction()?;ensure!(t.execute("UPDATE protected_services SET deleted=1,revision=revision+1 WHERE id=? AND deleted=0",[id])?==1,"service not found");
            t.execute("DELETE FROM service_sources WHERE service_id=?",[id])?;
            t.execute("INSERT INTO events(at,kind,detail) VALUES(?,'service_deleted',?)",params![now,serde_json::json!({"service_id":id,"actor":"admin","existing_bans":"retained_until_expiry"}).to_string()])?;
            t.commit()?;Ok(())}).await
    }
    /// Explicit recovery changes revision to invalidate in-flight decisions.
    pub async fn reset_service_source(&self, id: i64, source_id: String, now: i64) -> Result<()> {
        self.call(move |c| {
            let t = c.transaction()?;
            let data: String = t.query_row(
                "SELECT data FROM protected_services WHERE id=? AND deleted=0",
                [id],
                |r| r.get(0),
            )?;
            let mut service: ProtectedService = serde_json::from_str(&data)?;
            ensure!(
                service.sources.iter().any(|s| s.id == source_id),
                "source not found"
            );
            service.revision += 1;
            t.execute(
                "DELETE FROM service_sources WHERE service_id=? AND source_id=?",
                params![id, source_id],
            )?;
            t.execute(
                "UPDATE protected_services SET revision=?,data=? WHERE id=?",
                params![service.revision, serde_json::to_string(&service)?, id],
            )?;
            t.execute(
                "INSERT INTO events(at,kind,detail) VALUES(?,'service_source_reset',?)",
                params![
                    now,
                    serde_json::json!({"service_id":id,"source_id":source_id,"actor":"admin"})
                        .to_string()
                ],
            )?;
            t.commit()?;
            Ok(())
        })
        .await
    }
    pub async fn source_states(&self, id: i64) -> Result<BTreeMap<String, SourceState>> {
        self.read(move |c| {
            let mut s =
                c.prepare("SELECT source_id,data FROM service_sources WHERE service_id=?")?;
            s.query_map([id], |r| {
                Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?))
            })?
            .map(|r| {
                let (id, data) = r?;
                Ok((id, serde_json::from_str(&data)?))
            })
            .collect()
        })
        .await
    }
    pub async fn source_state(&self, id: i64, source: &LogSource) -> Result<SourceState> {
        let source = source.clone();
        self.read(move|c| { let data:Option<String>=c.query_row("SELECT data FROM service_sources WHERE service_id=? AND source_id=? AND input=?",params![id,source.id,serde_json::to_string(&source.input)?],|r|r.get(0)).optional()?;
            Ok(data.map(|d|serde_json::from_str(&d)).transpose()?.unwrap_or_default()) }).await
    }
    /// Events and read position advance together; callers evaluate only returned new observations.
    pub async fn service_checkpoint(
        &self,
        service: ProtectedService,
        source: LogSource,
        mut state: SourceState,
        events: Vec<(String, SecurityEvent)>,
    ) -> Result<Vec<SecurityEvent>> {
        ensure!(events.len() <= 8192, "source batch limit exceeded");
        self.call(move|c| {
            let t=c.transaction()?;
            let revision:i64=t.query_row("SELECT revision FROM protected_services WHERE id=? AND deleted=0",[service.id],|r|r.get(0))?;
            ensure!(revision==service.revision,"configuration changed during source read");
            state.revision=service.revision;
            let mut new=vec![];
            for (key,e) in events {
                if t.execute("INSERT OR IGNORE INTO security_events(service_id,at,event_key,data) VALUES(?,?,?,?)",params![service.id,e.at,key,serde_json::to_string(&e)?])?==1 {new.push(e);}
            }
            if !new.is_empty() {
                let count:i64=t.query_row("SELECT count(*) FROM security_events",[],|r|r.get(0))?;
                if count>100000 {t.execute("DELETE FROM security_events WHERE id IN (SELECT id FROM security_events ORDER BY id LIMIT ?)",[count-100000])?;}
            }
            t.execute("INSERT INTO service_sources(service_id,source_id,input,data) VALUES(?,?,?,?) ON CONFLICT(service_id,source_id) DO UPDATE SET input=excluded.input,data=excluded.data",params![service.id,source.id,serde_json::to_string(&source.input)?,serde_json::to_string(&state)?])?;
            t.commit()?;Ok(new)
        }).await
    }
    pub async fn security_events(&self, id: i64, limit: usize) -> Result<Vec<StoredEvent>> {
        self.read(move|c| {
            let mut statement=c.prepare("SELECT id,data FROM security_events WHERE service_id=? ORDER BY at DESC,id DESC LIMIT ?")?;
            let mut rows=statement.query(params![id,limit.min(10000) as i64])?;
            let mut out=vec![];let mut bytes=0;
            while let Some(row)=rows.next()? {
                let data:String=row.get(1)?;bytes+=data.len();
                if bytes>4*1024*1024 {break;}
                out.push(StoredEvent{id:row.get(0)?,event:serde_json::from_str(&data)?});
            }
            Ok(out)
        }).await
    }
    pub async fn security_event_count(&self, id: i64) -> Result<usize> {
        self.read(move |c| {
            Ok(c.query_row(
                "SELECT count(*) FROM security_events WHERE service_id=?",
                [id],
                |r| r.get::<_, i64>(0),
            )? as usize)
        })
        .await
    }
    pub async fn prune_service_history(&self, now: i64, days: i64) -> Result<()> {
        self.call(move |c| {
            let t = c.transaction()?;
            t.execute(
                "DELETE FROM security_events WHERE at<?",
                [now - days * 86400],
            )?;
            t.execute(
                "DELETE FROM service_decisions WHERE at<?",
                [now - days * 86400],
            )?;
            t.commit()?;
            Ok(())
        })
        .await
    }

    /// The global monitor chooses the status. Attribution and the existing rule/audit are atomic.
    pub async fn service_decision(
        &self,
        hit: PolicyHit,
        status: String,
        now: i64,
    ) -> Result<Option<Rule>> {
        self.call(move|c| {
            let t=c.transaction()?;
            let data:String=t.query_row("SELECT data FROM protected_services WHERE id=? AND deleted=0",[hit.service_id],|r|r.get(0))?;
            let service:ProtectedService=serde_json::from_str(&data)?;
            ensure!(service.enabled && service.revision==hit.revision,"stale or disabled service decision");
            let mut rule=None;
            if status=="pending" {
                ensure!(!service.observe_only && service.policies.iter().any(|p|p.id==hit.policy_id && p.enabled && !p.observe_only),"observe-only policy cannot enforce");
                let count:i64=t.query_row("SELECT count(*) FROM rules WHERE enabled=1 AND (expires IS NULL OR expires>?)",[now],|r|r.get(0))?;
                ensure!(count<1024,"rule capacity reached");
                let r=Rule{id:0,network:hit.source_ip.into(),kind:RuleKind::Block,reason:format!("{} / {}: {} {} events in {}s",hit.service_name,hit.policy_name,hit.count,hit.evidence.event_type,hit.window_seconds),actor:format!("service:{}:policy:{}",hit.service_id,hit.policy_id),created:now,expires:Some(now+hit.ban_seconds),enabled:true,applied:false,error:None};
                t.execute("INSERT INTO rules(network,kind,reason,actor,created,expires,enabled,applied) VALUES(?,'block',?,?,?,?,1,0)",params![r.network.to_string(),r.reason,r.actor,now,r.expires])?;
                let r=Rule{id:t.last_insert_rowid(),..r};
                t.execute("INSERT INTO events(at,kind,detail) VALUES(?,'rule_created',?)",params![now,serde_json::to_string(&r)?])?;
                rule=Some(r);
            }
            t.execute("INSERT INTO service_decisions(service_id,at,data,status,rule_id) VALUES(?,?,?,?,?)",params![hit.service_id,now,serde_json::to_string(&hit)?,status,rule.as_ref().map(|r|r.id)])?;
            t.execute("INSERT INTO events(at,kind,detail) VALUES(?,'service_decision',?)",params![now,serde_json::json!({"hit":hit,"status":status,"rule_id":rule.as_ref().map(|r|r.id)}).to_string()])?;
            let count:i64=t.query_row("SELECT count(*) FROM service_decisions",[],|r|r.get(0))?;
            if count>10000 {t.execute("DELETE FROM service_decisions WHERE id IN (SELECT id FROM service_decisions ORDER BY id LIMIT ?)",[count-10000])?;}
            t.commit()?;Ok(rule)
        }).await
    }
    pub async fn service_decisions(&self, id: i64) -> Result<Vec<Decision>> {
        self.read(move|c|{let mut s=c.prepare("SELECT d.id,d.data,d.status,d.rule_id,r.network,r.reason,r.actor,r.created,r.expires,r.enabled,r.applied,r.error FROM service_decisions d LEFT JOIN rules r ON r.id=d.rule_id WHERE d.service_id=? ORDER BY d.id DESC LIMIT 200")?;
            s.query_map([id],|r|Ok((r.get::<_,i64>(0)?,r.get::<_,String>(1)?,r.get::<_,String>(2)?,r.get::<_,Option<i64>>(3)?,r.get::<_,Option<String>>(4)?,r.get::<_,Option<String>>(5)?,r.get::<_,Option<String>>(6)?,r.get::<_,Option<i64>>(7)?,r.get::<_,Option<i64>>(8)?,r.get::<_,Option<bool>>(9)?,r.get::<_,Option<bool>>(10)?,r.get::<_,Option<String>>(11)?)))?.map(|row|{let (id,data,status,rule_id,network,reason,actor,created,expires,enabled,applied,error)=row?;
                let rule=if let Some(network)=network{Some(Rule{id:rule_id.unwrap(),network:network.parse()?,kind:RuleKind::Block,reason:reason.unwrap(),actor:actor.unwrap(),created:created.unwrap(),expires,enabled:enabled.unwrap(),applied:applied.unwrap(),error})}else{None};
                Ok(Decision{id,hit:serde_json::from_str(&data)?,status,rule_id,rule})}).collect()
        }).await
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[tokio::test]
    async fn checkpoint_dedup_and_revision() {
        let db = Database::open(":memory:").unwrap();
        let s = db.save_service(ssh_template(), true, 100).await.unwrap();
        let event = playground(
            &s,
            "ssh-journal",
            "Failed password for root from 192.0.2.1 port 44",
            100,
            1,
        )
        .unwrap()
        .matches[0]
            .event
            .clone()
            .unwrap();
        for expected in [1, 0] {
            let new = db
                .service_checkpoint(
                    s.clone(),
                    s.sources[0].clone(),
                    SourceState {
                        cursor: "cursor".into(),
                        ..Default::default()
                    },
                    vec![("key".into(), event.clone())],
                )
                .await
                .unwrap();
            assert_eq!(new.len(), expected);
        }
        assert_eq!(
            db.source_states(s.id).await.unwrap()["ssh-journal"].cursor,
            "cursor"
        );
        db.save_service(s.clone(), false, 101).await.unwrap();
        assert!(db.save_service(s, false, 102).await.is_err());
    }
    #[tokio::test]
    async fn independent_bans_survive_delete() {
        let db = Database::open(":memory:").unwrap();
        let mut s = db.save_service(ssh_template(), true, 100).await.unwrap();
        s.observe_only = false;
        s.policies[0].observe_only = false;
        s.policies[0].threshold = 1;
        s = db.save_service(s, false, 101).await.unwrap();
        let hit = playground(
            &s,
            "ssh-journal",
            "Failed password for root from 192.0.2.1 port 44",
            102,
            1,
        )
        .unwrap()
        .decisions[0]
            .clone();
        let now = crate::unix_now();
        let r = db
            .service_decision(hit.clone(), "pending".into(), now)
            .await
            .unwrap()
            .unwrap();
        let r2 = db
            .service_decision(hit, "pending".into(), now)
            .await
            .unwrap()
            .unwrap();
        db.remove_rule(r.id, now).await.unwrap();
        db.delete_service(s.id, now).await.unwrap();
        assert_eq!(db.rules().await.unwrap()[0].id, r2.id);
        assert_eq!(db.service_decisions(s.id).await.unwrap().len(), 2);
    }
    #[tokio::test]
    async fn failure_rolls_back_events_cursors_rules_and_attribution() {
        let db = Database::open(":memory:").unwrap();
        let mut service = db.save_service(ssh_template(), true, 100).await.unwrap();
        service.observe_only = false;
        service.policies[0].observe_only = false;
        service.policies[0].threshold = 1;
        service = db.save_service(service, false, 101).await.unwrap();
        let hit = playground(
            &service,
            "ssh-journal",
            "Failed password for root from 192.0.2.1 port 44",
            102,
            1,
        )
        .unwrap()
        .decisions[0]
            .clone();
        db.call(|c| {c.execute_batch("CREATE TRIGGER reject_attribution BEFORE INSERT ON service_decisions BEGIN SELECT RAISE(ABORT,'test attribution failure'); END; CREATE TRIGGER reject_cursor BEFORE INSERT ON service_sources BEGIN SELECT RAISE(ABORT,'test cursor failure'); END;")?;Ok(())}).await.unwrap();
        assert!(
            db.service_decision(hit.clone(), "pending".into(), crate::unix_now())
                .await
                .is_err()
        );
        assert!(db.rules().await.unwrap().is_empty());
        assert!(
            db.service_checkpoint(
                service.clone(),
                service.sources[0].clone(),
                SourceState::default(),
                vec![("observation".into(), hit.evidence)],
            )
            .await
            .is_err()
        );
        assert!(
            db.security_events(service.id, 100)
                .await
                .unwrap()
                .is_empty()
        );
        assert!(db.source_states(service.id).await.unwrap().is_empty());
        assert!(
            db.events(100, i64::MAX)
                .await
                .unwrap()
                .iter()
                .all(|e| e.kind != "rule_created")
        );
    }
    #[tokio::test]
    async fn schema_three_backup_and_restart_preserve_services_and_positions() {
        let path = std::env::temp_dir().join(format!(
            "einblick-service-migration-{}.sqlite",
            crate::unix_now()
        ));
        let name = path.to_str().unwrap();
        let db = Database::open(name).unwrap();
        db.call(|c| {c.execute_batch("DROP TABLE service_sources;DROP TABLE security_events;DROP TABLE service_decisions;DROP TABLE protected_services;PRAGMA user_version=3;")?;Ok(())}).await.unwrap();
        drop(db);
        let db = Database::open(name).unwrap();
        let service = db.save_service(ssh_template(), true, 100).await.unwrap();
        db.service_checkpoint(
            service.clone(),
            service.sources[0].clone(),
            SourceState {
                cursor: "persisted".into(),
                ..Default::default()
            },
            vec![],
        )
        .await
        .unwrap();
        drop(db);
        let reopened = Database::open(name).unwrap();
        assert_eq!(reopened.services().await.unwrap()[0].revision, 1);
        assert_eq!(
            reopened.source_states(service.id).await.unwrap()["ssh-journal"].cursor,
            "persisted"
        );
        let backup = rusqlite::Connection::open(format!("{name}.schema-v3-backup")).unwrap();
        assert_eq!(
            backup
                .pragma_query_value(None, "user_version", |r| r.get::<_, i64>(0))
                .unwrap(),
            3
        );
        drop(backup);
        drop(reopened);
        for suffix in ["", "-wal", "-shm", ".schema-v3-backup"] {
            let _ = std::fs::remove_file(format!("{name}{suffix}"));
        }
    }
}
