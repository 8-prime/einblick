use crate::backend::{Backend, Observation};
use anyhow::{Result, ensure};
use einblick_core::{detector::Detector, storage::Database, *};
use ipnet::IpNet;
use std::{collections::HashMap, net::IpAddr, sync::Arc};
use tokio::sync::{RwLock, broadcast, mpsc, oneshot};

pub enum Action {
    Add {
        network: IpNet,
        kind: RuleKind,
        reason: String,
        seconds: Option<i64>,
    },
    Remove(i64),
    Mode {
        automatic: bool,
        blocking: bool,
        acknowledged: bool,
    },
    Emergency,
}
pub struct Command {
    pub action: Action,
    pub reply: oneshot::Sender<Result<()>>,
}
pub struct Monitor {
    config: Config,
    db: Database,
    backend: Backend,
    rules: Vec<Rule>,
    automatic: bool,
    blocking: bool,
    detector: Detector,
    previous: Totals,
    sources: HashMap<IpAddr, Source>,
    ports: HashMap<(u8, u16), u64>,
    recent: Vec<Detection>,
    bucket: Aggregate,
    pub snapshot: Arc<RwLock<Snapshot>>,
    pub updates: broadcast::Sender<Snapshot>,
    dirty: bool,
    storage_ok: bool,
    enforcement_ok: bool,
    last_error: Option<String>,
    last_poll: std::time::Instant,
    last_tick: i64,
}
impl Monitor {
    pub async fn new(
        config: Config,
        db: Database,
        snapshot: Arc<RwLock<Snapshot>>,
        updates: broadcast::Sender<Snapshot>,
    ) -> Result<Self> {
        let mut rules = db.rules().await?;
        let (automatic, blocking) = db.settings().await?;
        let automatic = automatic && !config.management_allowlist.is_empty();
        let mut backend = Backend::new(&config)?;
        backend.reconcile(&rules, &config.management_allowlist, blocking, unix_now())?;
        backend.attach(&config)?;
        for r in &mut rules {
            r.applied = r.active(unix_now()) && (r.kind == RuleKind::Allow || blocking);
            r.error = None;
        }
        db.applied(rules.clone()).await?;
        let detector = Detector::new(config.detection.clone(), config.source_capacity as usize);
        Ok(Self {
            config,
            db,
            backend,
            rules,
            automatic,
            blocking,
            detector,
            previous: Totals::default(),
            sources: HashMap::new(),
            ports: HashMap::new(),
            recent: vec![],
            bucket: Aggregate {
                at: unix_now() / 60 * 60,
                totals: Totals::default(),
                sources: vec![],
                ports: vec![],
                complete: true,
            },
            snapshot,
            updates,
            dirty: false,
            storage_ok: true,
            enforcement_ok: true,
            last_error: None,
            last_poll: std::time::Instant::now(),
            last_tick: 0,
        })
    }
    pub async fn run(
        mut self,
        mut commands: mpsc::Receiver<Command>,
        mut stop: broadcast::Receiver<()>,
    ) {
        let mut interval = tokio::time::interval(std::time::Duration::from_secs(1));
        interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        loop {
            tokio::select! {
                _=stop.recv()=>break,
                command=commands.recv()=> {let Some(command)=command else{break};let result=self.command(command.action).await;self.publish(Totals::default(),false).await;let _=command.reply.send(result);},
                _=interval.tick()=>self.tick().await,
            }
        }
        // Persist partial minute, then owned links detach when backend is dropped.
        if self.bucket.totals.packets > 0
            && let Err(e) = self
                .db
                .aggregate(self.bucket.clone(), self.config.retention.clone())
                .await
        {
            tracing::error!(%e,"final aggregate write failed");
        }
    }
    async fn command(&mut self, action: Action) -> Result<()> {
        let now = unix_now();
        match action {
            Action::Add {
                network,
                kind,
                reason,
                seconds,
            } => {
                ensure!(
                    !reason.trim().is_empty() && reason.len() <= 512,
                    "reason must contain 1–512 characters"
                );
                ensure!(
                    seconds.is_none_or(|s| s > 0 && s <= 365 * 86400),
                    "expiry must be 1 second to 365 days, or null for permanent"
                );
                let network = network.trunc();
                ensure!(
                    !self
                        .rules
                        .iter()
                        .any(|r| r.network == network && r.kind == kind && r.active(now)),
                    "an active rule already exists for this network and kind"
                );
                let r = self
                    .db
                    .insert_rule(Rule {
                        id: 0,
                        network,
                        kind,
                        reason,
                        actor: "admin".into(),
                        created: now,
                        expires: seconds.map(|s| now + s),
                        enabled: true,
                        applied: false,
                        error: None,
                    })
                    .await?;
                self.rules.push(r);
                self.dirty = true;
                // A manual block is an explicit request to enforce it.
                if !self.blocking && self.rules.last().is_some_and(|r| r.kind == RuleKind::Block) {
                    self.db.set_mode(self.automatic, true, now).await?;
                    self.blocking = true;
                }
            }
            Action::Remove(id) => {
                self.db.remove_rule(id, now).await?;
                if let Some(r) = self.rules.iter_mut().find(|r| r.id == id) {
                    r.enabled = false;
                }
                self.dirty = true;
            }
            Action::Mode {
                automatic,
                blocking,
                acknowledged,
            } => {
                ensure!(
                    !automatic || blocking,
                    "automatic bans require blocking enabled"
                );
                ensure!(
                    !automatic || (!self.config.management_allowlist.is_empty() && acknowledged),
                    "configure management_allowlist and acknowledge observe-mode evidence first"
                );
                ensure!(
                    !automatic || (self.storage_ok && self.enforcement_ok),
                    "resolve health errors before enabling automatic bans"
                );
                self.db.set_mode(automatic, blocking, now).await?;
                self.automatic = automatic;
                self.blocking = blocking;
                self.dirty = true;
            }
            Action::Emergency => {
                // Disable in kernel even when storage is unavailable.
                self.backend.emergency()?;
                self.automatic = false;
                self.blocking = false;
                self.dirty = false;
                if let Err(e) = self.db.set_mode(false, false, now).await {
                    self.storage_ok = false;
                    self.last_error = Some(format!(
                        "blocking disabled, but restart state was not persisted: {e}"
                    ));
                    return Err(e);
                }
            }
        }
        self.reconcile().await;
        Ok(())
    }
    async fn reconcile(&mut self) {
        if !self.dirty {
            return;
        }
        match self.backend.reconcile(
            &self.rules,
            &self.config.management_allowlist,
            self.blocking,
            unix_now(),
        ) {
            Ok(()) => {
                self.dirty = false;
                self.enforcement_ok = true;
                for r in &mut self.rules {
                    r.applied =
                        r.active(unix_now()) && (r.kind == RuleKind::Allow || self.blocking);
                    r.error = None;
                }
            }
            Err(e) => {
                self.enforcement_ok = false;
                self.last_error = Some(e.to_string());
                for r in &mut self.rules {
                    r.applied = false;
                    r.error = Some(e.to_string());
                }
            }
        }
        if let Err(e)=self.db.event(unix_now(),"enforcement_reconciled",serde_json::json!({"blocking":self.blocking,"success":self.enforcement_ok,"rules":self.rules})).await {self.storage_ok=false;self.last_error=Some(e.to_string());}
        if let Err(e) = self.db.applied(self.rules.clone()).await {
            self.storage_ok = false;
            self.last_error = Some(e.to_string());
        }
    }
    async fn tick(&mut self) {
        let elapsed = self.last_poll.elapsed().as_secs_f64();
        self.last_poll = std::time::Instant::now();
        let now = unix_now();
        if self.bucket.at != now / 60 * 60 {
            let old = std::mem::replace(
                &mut self.bucket,
                Aggregate {
                    at: now / 60 * 60,
                    totals: Totals::default(),
                    sources: vec![],
                    ports: vec![],
                    complete: true,
                },
            );
            match self.db.aggregate(old, self.config.retention.clone()).await {
                Ok(()) => self.storage_ok = true,
                Err(e) => {
                    self.storage_ok = false;
                    self.last_error = Some(e.to_string());
                }
            }
            if self.rules.iter().any(|r| !r.active(now)) {
                self.dirty = true;
            }
            self.rules
                .retain(|r| r.enabled && (r.expires.is_none_or(|e| e > now)));
        }
        // Rebuild when expiry changes desired rules (even if kernel already expired them).
        if self.rules.iter().any(|r| r.applied && !r.active(now)) {
            self.dirty = true;
        }
        self.reconcile().await;
        let observation = match self.backend.poll() {
            Ok(o) => o,
            Err(e) => {
                self.last_error = Some(e.to_string());
                self.detector.clear();
                self.publish(Totals::default(), false).await;
                return;
            }
        };
        self.process(now, elapsed, observation).await;
    }
    async fn process(&mut self, now: i64, elapsed: f64, o: Observation) {
        self.last_tick = now;
        let rate = o.totals.delta(&self.previous);
        let mut complete =
            o.complete && rate.event_loss == 0 && rate.map_full == 0 && elapsed <= 1.5;
        self.previous = o.totals;
        let mut sources = HashMap::new();
        let mut rates = vec![];
        let mut delta_sources = vec![];
        for s in o.sources {
            let old = self.sources.get(&s.ip);
            let delta = Source {
                ip: s.ip,
                packets: s.packets.saturating_sub(old.map_or(0, |v| v.packets)),
                bytes: s.bytes.saturating_sub(old.map_or(0, |v| v.bytes)),
                syns: s.syns.saturating_sub(old.map_or(0, |v| v.syns)),
            };
            rates.push((s.ip, delta.packets, delta.syns));
            delta_sources.push(delta);
            sources.insert(s.ip, s);
        }
        self.sources = sources;
        let mut ports = HashMap::new();
        let mut delta_ports = vec![];
        for p in o.ports {
            let k = (p.protocol, p.port);
            let delta = p.packets.saturating_sub(*self.ports.get(&k).unwrap_or(&0));
            delta_ports.push(Port {
                packets: delta,
                ..p
            });
            ports.insert(k, p.packets);
        }
        self.ports = ports;
        self.bucket.totals.add(&rate);
        self.bucket.complete &= complete;
        for s in delta_sources {
            if let Some(old) = self.bucket.sources.iter_mut().find(|v| v.ip == s.ip) {
                old.packets += s.packets;
                old.bytes += s.bytes;
                old.syns += s.syns;
            } else {
                self.bucket.sources.push(s);
            }
        }
        self.bucket
            .sources
            .sort_by_key(|s| std::cmp::Reverse(s.packets));
        self.bucket.sources.truncate(100);
        for p in delta_ports {
            if let Some(old) = self
                .bucket
                .ports
                .iter_mut()
                .find(|v| v.protocol == p.protocol && v.port == p.port)
            {
                old.packets += p.packets;
            } else {
                self.bucket.ports.push(p);
            }
        }
        self.bucket
            .ports
            .sort_by_key(|p| std::cmp::Reverse(p.packets));
        self.bucket
            .ports
            .truncate(self.config.port_capacity as usize);
        let detections = self.detector.tick(
            (crate::backend::monotonic_ns() / 1_000_000_000) as i64,
            &rates,
            &o.syns,
            complete,
        );
        complete &= self.detector.evidence_complete;
        self.bucket.complete &= complete;
        for mut d in detections {
            d.at = now;
            if let Err(e) = self
                .db
                .event(now, "detection", serde_json::to_value(&d).unwrap())
                .await
            {
                self.storage_ok = false;
                self.last_error = Some(e.to_string());
            }
            let allowed = self
                .config
                .management_allowlist
                .iter()
                .any(|n| n.contains(&d.ip))
                || self.rules.iter().any(|r| {
                    r.kind == RuleKind::Allow && r.active(now) && r.network.contains(&d.ip)
                });
            if self.automatic
                && self.blocking
                && self.storage_ok
                && self.enforcement_ok
                && d.eligible
                && !allowed
                && !self.rules.iter().any(|r| {
                    r.kind == RuleKind::Block && r.active(now) && r.network.contains(&d.ip)
                })
            {
                match self
                    .db
                    .insert_rule(Rule {
                        id: 0,
                        network: IpNet::from(d.ip),
                        kind: RuleKind::Block,
                        reason: format!("{}: {}", d.kind, d.evidence),
                        actor: "detector".into(),
                        created: now,
                        expires: Some(now + self.config.detection.ban_seconds),
                        enabled: true,
                        applied: false,
                        error: None,
                    })
                    .await
                {
                    Ok(r) => {
                        self.rules.push(r);
                        self.dirty = true;
                    }
                    Err(e) => {
                        self.storage_ok = false;
                        self.last_error = Some(e.to_string());
                    }
                }
            }
            self.recent.push(d);
            if self.recent.len() > 100 {
                self.recent.remove(0);
            }
        }
        self.reconcile().await;
        self.publish(rate, complete).await;
    }
    async fn publish(&self, rate: Totals, complete: bool) {
        let (backend, attachments) = self.backend.description();
        let mut sources = self.sources.values().cloned().collect::<Vec<_>>();
        sources.sort_by_key(|s| std::cmp::Reverse(s.packets));
        sources.truncate(100);
        let mut ports = self
            .ports
            .iter()
            .map(|(&(protocol, port), &packets)| Port {
                protocol,
                port,
                packets,
            })
            .collect::<Vec<_>>();
        ports.sort_by_key(|p| std::cmp::Reverse(p.packets));
        ports.truncate(100);
        let snap = Snapshot {
            at: unix_now(),
            totals: self.previous.clone(),
            rate,
            sources,
            ports,
            detections: self.recent.clone(),
            rules: self.rules.clone(),
            automatic: self.automatic,
            blocking: self.blocking,
            health: Health {
                backend,
                attachments,
                telemetry_complete: complete,
                storage_ok: self.storage_ok,
                enforcement_ok: self.enforcement_ok,
                last_error: self.last_error.clone(),
                last_tick: self.last_tick,
            },
        };
        *self.snapshot.write().await = snap.clone();
        let _ = self.updates.send(snap);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    async fn monitor(allowlist: bool) -> Monitor {
        let mut c = Config {
            mock: true,
            secure_cookies: false,
            public_origin: "http://localhost".into(),
            ..Config::default()
        };
        if allowlist {
            c.management_allowlist = vec!["192.0.2.24/32".parse().unwrap()];
        }
        c.detection.syns_10s = 10;
        let db = Database::open(":memory:").unwrap();
        let snapshot = Arc::new(RwLock::new(Snapshot::default()));
        let (updates, _) = broadcast::channel(4);
        Monitor::new(c, db, snapshot, updates).await.unwrap()
    }
    #[tokio::test]
    async fn activation_requires_management_and_acknowledgment() {
        let mut m = monitor(false).await;
        assert!(
            m.command(Action::Mode {
                automatic: true,
                blocking: true,
                acknowledged: true
            })
            .await
            .is_err()
        );
        let mut m = monitor(true).await;
        assert!(
            m.command(Action::Mode {
                automatic: true,
                blocking: true,
                acknowledged: false
            })
            .await
            .is_err()
        );
        m.command(Action::Mode {
            automatic: true,
            blocking: true,
            acknowledged: true,
        })
        .await
        .unwrap();
        assert!(m.automatic);
    }
    #[tokio::test]
    async fn detection_bans_are_audited_and_allowlist_is_protected() {
        let mut m = monitor(true).await;
        m.command(Action::Mode {
            automatic: true,
            blocking: true,
            acknowledged: true,
        })
        .await
        .unwrap();
        let mut o = m.backend.poll().unwrap();
        o.sources[0].syns = 20;
        o.sources[1].syns = 20;
        m.process(unix_now(), 1.0, o).await;
        assert!(m.rules.iter().any(|r| r.actor == "detector" && r.applied));
        assert!(!m.rules.iter().any(|r| r.kind == RuleKind::Block
            && r.network.contains(&"192.0.2.24".parse::<IpAddr>().unwrap())));
        assert!(
            m.db.events(100, i64::MAX)
                .await
                .unwrap()
                .iter()
                .any(|e| e.kind == "enforcement_reconciled")
        );
        m.command(Action::Emergency).await.unwrap();
        assert!(!m.blocking && !m.automatic);
    }
    #[tokio::test]
    async fn incomplete_telemetry_and_audit_failure_prevent_bans() {
        let mut m = monitor(true).await;
        m.command(Action::Mode {
            automatic: true,
            blocking: true,
            acknowledged: true,
        })
        .await
        .unwrap();
        let mut o = m.backend.poll().unwrap();
        o.complete = false;
        m.process(unix_now(), 1.0, o).await;
        assert!(m.rules.is_empty());
        m.db.call(|c| {
            c.execute_batch("DROP TABLE events")?;
            Ok(())
        })
        .await
        .unwrap();
        let o = m.backend.poll().unwrap();
        m.process(unix_now() + 1, 1.0, o).await;
        assert!(!m.storage_ok && m.rules.is_empty());
        // Emergency kernel disable works even if persisting the mode fails.
        assert!(m.command(Action::Emergency).await.is_err());
        assert!(!m.blocking && !m.automatic);
    }
}
