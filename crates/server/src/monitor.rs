use crate::backend::{Backend, Observation};
use anyhow::{Result, ensure};
use einblick_core::{detector::Detector, storage::Database, *};
use ipnet::IpNet;
use std::{
    collections::{BTreeMap, BTreeSet, HashMap, VecDeque},
    net::IpAddr,
    sync::Arc,
};
use tokio::sync::{RwLock, broadcast, mpsc, oneshot};

pub enum Action {
    ServiceDecision {
        hit: Box<einblick_core::services::PolicyHit>,
        complete: bool,
    },
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
    management: crate::management::ManagementAllowlist,
    db: Database,
    backend: Backend,
    rules: Vec<Rule>,
    automatic: bool,
    blocking: bool,
    detector: Detector,
    previous: Totals,
    persisted_totals: Totals,
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
    detection_complete: bool,
    detail_complete: bool,
    reasons: Vec<String>,
    maps: Vec<MapHealth>,
    pub live_traffic: Arc<RwLock<LiveTraffic>>,
    detail: BTreeMap<TrafficKey, TrafficRecord>,
    detail_keys: BTreeSet<TrafficKey>,
    detail_queue: VecDeque<DetailBatch>,
    detail_writer: Option<tokio::task::JoinHandle<Result<()>>>,
    detail_run: String,
    detail_sequence: u64,
    detail_from: i64,
    detail_bucket: i64,
    detail_ok: bool,
    detail_omitted: u64,
    detail_gap_from: Option<i64>,
    detail_storage_ok: bool,
    evidence_gap: bool,
    pub applications: crate::applications::Reader,
    pub ip_enrichment: crate::ip_enrichment::Enrichment,
    application_bytes: usize,
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
        let management = crate::management::ManagementAllowlist::new(&config).await;
        let mut backend = Backend::new(&config)?;
        backend.reconcile(&rules, &management.networks, blocking, unix_now())?;
        backend.attach(&config)?;
        for r in &mut rules {
            r.applied = r.active(unix_now()) && (r.kind == RuleKind::Allow || blocking);
            r.error = None;
        }
        db.applied(rules.clone()).await?;
        let detector = Detector::new(config.detection.clone(), config.source_capacity as usize);
        let applications = crate::applications::Reader::disabled(config.applications.clone());
        let persisted_totals = db.overview_totals().await?;
        let monitor = Self {
            config,
            management,
            db,
            backend,
            rules,
            automatic,
            blocking,
            detector,
            previous: Totals::default(),
            persisted_totals,
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
            detection_complete: false,
            detail_complete: false,
            reasons: vec!["Waiting for first observation".into()],
            maps: vec![],
            live_traffic: Arc::new(RwLock::new(LiveTraffic::default())),
            detail: BTreeMap::new(),
            detail_keys: BTreeSet::new(),
            detail_queue: VecDeque::new(),
            detail_writer: None,
            detail_run: hex::encode(rand::random::<[u8; 16]>()),
            detail_sequence: 1,
            detail_from: unix_now(),
            detail_bucket: unix_now() / 60 * 60,
            detail_ok: true,
            detail_omitted: 0,
            detail_gap_from: None,
            detail_storage_ok: true,
            evidence_gap: false,
            applications,
            ip_enrichment: crate::ip_enrichment::Enrichment::default(),
            application_bytes: 0,
        };
        monitor.publish(Totals::default(), false).await;
        Ok(monitor)
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
                command=commands.recv()=> {let Some(command)=command else{break};let result=self.command(command.action).await;self.publish(Totals::default(),self.detection_complete && self.detail_complete).await;let _=command.reply.send(result);},
                _=interval.tick()=>self.tick().await,
            }
        }
        // Persist partial minute, then owned links detach when backend is dropped.
        if let Some(writer) = self.detail_writer.take() {
            match writer.await {
                Ok(Ok(())) => {
                    self.detail_queue.pop_front();
                }
                other => tracing::error!(?other, "detail checkpoint failed at shutdown"),
            }
        }
        self.flush_detail(unix_now());
        while let Some(batch) = self.detail_queue.pop_front() {
            if let Err(e) = self
                .db
                .detail_checkpoint(
                    batch,
                    self.config.retention.clone(),
                    self.config.detail_row_limit,
                )
                .await
            {
                tracing::error!(%e,"final detail checkpoint failed");
                break;
            }
        }
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
            Action::ServiceDecision { hit, complete } => {
                let allowed = self
                    .management
                    .networks
                    .iter()
                    .any(|n| n.contains(&hit.source_ip))
                    || self.rules.iter().any(|r| {
                        r.kind == RuleKind::Allow
                            && r.active(now)
                            && r.network.contains(&hit.source_ip)
                    });
                let actor = format!("service:{}:policy:{}", hit.service_id, hit.policy_id);
                let status = if !complete {
                    "incomplete_evidence"
                } else if hit.observe_only {
                    "observe_only"
                } else if allowed {
                    "allowlisted"
                } else if !self.automatic || !self.blocking {
                    "global_observe"
                } else if !self.storage_ok
                    || !self.management.ready()
                    || !self.detail_storage_ok
                    || !self.enforcement_ok
                    || !self.db.healthy.load(std::sync::atomic::Ordering::Acquire)
                {
                    "health_suspended"
                } else if self.rules.iter().any(|r| {
                    r.actor == actor && r.network.contains(&hit.source_ip) && r.active(now)
                }) {
                    "already_active"
                } else {
                    "pending"
                };
                if let Some(rule) = self.db.service_decision(*hit, status.into(), now).await? {
                    self.rules.push(rule);
                    self.dirty = true;
                }
            }
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
                    !automatic || (self.management.ready() && acknowledged),
                    "configure management_allowlist, resolve all management hostnames, and acknowledge observe-mode evidence first"
                );
                ensure!(
                    !automatic
                        || (self.storage_ok && self.detail_storage_ok && self.enforcement_ok),
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
            &self.management.networks,
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
        if self.management.poll().await {
            self.dirty = true;
        }
        let now = unix_now();
        if self.clock_changed(now, elapsed) {
            self.detail_ok = false;
            self.detail_gap_from = Some(self.detail_from.min(now));
        }
        self.pump_detail().await;
        if now / 60 * 60 != self.detail_bucket {
            self.flush_detail(now);
            self.detail_keys.clear();
            self.detail_bucket = now / 60 * 60;
        } else if now - self.detail_from >= 10 {
            self.flush_detail(now);
        }
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
                self.detection_complete = false;
                self.detail_complete = false;
                self.detail_ok = false;
                self.evidence_gap = true;
                self.reasons = vec![format!("Capture poll failed: {e}")];
                self.publish(Totals::default(), false).await;
                return;
            }
        };
        self.process(now, elapsed, observation).await;
    }
    async fn process(&mut self, now: i64, elapsed: f64, o: Observation) {
        let clock_changed = self.clock_changed(now, elapsed);
        self.last_tick = now;
        let mut rate = o.totals.delta(&self.previous);
        rate.port_misses = o.port_misses;
        rate.association_misses = o.association_misses;
        let mut complete = o.complete
            && rate.event_loss == 0
            && rate.source_misses == 0
            && elapsed <= 1.5
            && !self.evidence_gap;
        self.detail_complete = o.detail_complete
            && rate.port_misses == 0
            && rate.association_misses == 0
            && elapsed <= 1.5
            && !clock_changed;
        self.maps = o.maps;
        self.reasons.clear();
        if self.evidence_gap {
            self.reasons
                .push("Rebuilding evidence after a capture gap".into());
        }
        self.evidence_gap = false;
        for (hit, reason) in [
            (
                rate.source_misses > 0,
                "Source map full; detection evidence incomplete",
            ),
            (
                rate.port_misses > 0,
                "Port map full; port summary incomplete",
            ),
            (
                rate.association_misses > 0,
                "IP detail map full; associations incomplete",
            ),
            (
                rate.event_loss > 0,
                "SYN events lost; detection evidence incomplete",
            ),
            (!o.complete, "Stale or truncated SYN evidence"),
            (elapsed > 1.5, "Polling interval exceeded 1.5 seconds"),
            (!o.detail_complete, "Detail map handover delayed"),
            (
                clock_changed,
                "System clock changed; traffic detail timing incomplete",
            ),
        ] {
            if hit {
                self.reasons.push(reason.into());
            }
        }
        self.previous = o.totals;
        let mut sources = HashMap::new();
        let mut rates = vec![];
        let mut delta_sources = vec![];
        for s in o.sources {
            let old = self
                .sources
                .get(&s.ip)
                .filter(|old| old.generation == s.generation);
            let delta = Source {
                ip: s.ip,
                packets: s.packets.saturating_sub(old.map_or(0, |v| v.packets)),
                bytes: s.bytes.saturating_sub(old.map_or(0, |v| v.bytes)),
                syns: s.syns.saturating_sub(old.map_or(0, |v| v.syns)),
                generation: s.generation,
                ip_info: None,
            };
            rates.push((s.ip, delta.packets, delta.syns));
            delta_sources.push(delta);
            sources.insert(s.ip, s);
        }
        self.sources = sources;
        let mut delta_ports = vec![];
        for p in o.ports {
            let k = (p.protocol, p.port);
            *self.ports.entry(k).or_default() += p.packets;
            delta_ports.push(p);
        }
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
        self.detection_complete = complete;
        if !self.detector.evidence_complete && self.reasons.is_empty() {
            self.reasons.push("Detector evidence window full".into());
        }
        self.detail_ok &= self.detail_complete;
        self.detail_omitted += rate.association_misses;
        for mut row in o.traffic {
            self.applications.enrich(&mut row);
            let key = row.key();
            if !self.detail_keys.contains(&key)
                && self.detail_keys.len() >= self.config.detail_minute_capacity
            {
                self.detail_ok = false;
                self.detail_complete = false;
                self.detail_omitted += row.counts.packets;
                continue;
            }
            self.detail_keys.insert(key.clone());
            let old = self.detail.get(&key).map(|r| &r.application_attribution);
            let bytes = |a: &ApplicationAttribution| {
                serde_json::to_vec(&a.applications).map_or(0, |v| v.len().saturating_sub(2))
            };
            let old_bytes = old.map_or(0, bytes);
            let mut merged = old.cloned().unwrap_or(ApplicationAttribution {
                applications: vec![],
                reasons: vec![],
            });
            merged.merge(&row.application_attribution);
            if self.application_bytes - old_bytes + bytes(&merged)
                > self.config.applications.batch_evidence_bytes
            {
                // Keep previous evidence but omit new candidates; counts are
                // still merged normally. Reserve base status bytes per row.
                merged = old.cloned().unwrap_or(ApplicationAttribution {
                    applications: vec![],
                    reasons: vec![],
                });
                merged.merge(&ApplicationAttribution::unknown(
                    ApplicationReason::Truncated,
                ));
            }
            self.application_bytes = self.application_bytes - old_bytes + bytes(&merged);
            if let Some(old) = self.detail.get_mut(&key) {
                old.merge(&row);
                old.application_attribution = merged;
            } else {
                row.application_attribution = merged;
                self.detail.insert(key, row);
            }
        }
        if !self.detail_complete && self.reasons.is_empty() {
            self.reasons
                .push("Minute IP detail capacity reached".into());
        }
        self.bucket.complete &= complete && self.detail_complete;
        self.publish_live(now).await;
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
            let allowed = self.management.networks.iter().any(|n| n.contains(&d.ip))
                || self.rules.iter().any(|r| {
                    r.kind == RuleKind::Allow && r.active(now) && r.network.contains(&d.ip)
                });
            if self.automatic
                && self.management.ready()
                && self.blocking
                && self.storage_ok
                && self.detail_storage_ok
                && self.enforcement_ok
                && d.eligible
                && !allowed
                && !self.rules.iter().any(|r| {
                    r.kind == RuleKind::Block
                        && r.actor == "detector"
                        && r.reason.starts_with(&format!("{}:", d.kind))
                        && r.active(now)
                        && r.network.contains(&d.ip)
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
        self.publish(rate, complete && self.detail_complete).await;
    }
    async fn publish(&self, rate: Totals, complete: bool) {
        let (backend, attachments) = self.backend.description();
        let mut sources = self.sources.values().cloned().collect::<Vec<_>>();
        sources.sort_by_key(|s| std::cmp::Reverse(s.packets));
        sources.truncate(100);
        for source in &mut sources {
            source.ip_info = self.ip_enrichment.lookup(source.ip);
        }
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
        let mut totals = self.persisted_totals.clone();
        totals.add(&self.previous);
        let snap = Snapshot {
            management_allowlist: self.management.networks.clone(),
            at: unix_now(),
            totals,
            session_totals: self.previous.clone(),
            rate,
            sources,
            ports,
            detections: self.recent.clone(),
            rules: self.rules.clone(),
            automatic: self.automatic,
            blocking: self.blocking,
            health: Health {
                management_dns: self.management.health(),
                ip_enrichment: self.ip_enrichment.health(),
                applications: self.applications.health(),
                backend,
                attachments,
                telemetry_complete: complete,
                detection_complete: self.detection_complete,
                detail_complete: self.detail_complete,
                reasons: self.reasons.clone(),
                maps: self.maps.clone(),
                storage_ok: self.storage_ok && self.detail_storage_ok,
                enforcement_ok: self.enforcement_ok,
                last_error: self.last_error.clone(),
                last_tick: self.last_tick,
            },
        };
        *self.snapshot.write().await = snap.clone();
        let _ = self.updates.send(snap);
    }
    fn current_detail(&self, now: i64) -> DetailBatch {
        DetailBatch {
            run: self.detail_run.clone(),
            sequence: self.detail_sequence,
            from: self.detail_from.min(now),
            to: now,
            rows: self.detail.values().cloned().collect(),
            complete: self.detail_ok && now >= self.detail_from,
            omitted: self.detail_omitted,
            gap_from: self.detail_gap_from,
        }
    }
    fn clock_changed(&self, now: i64, elapsed: f64) -> bool {
        self.last_tick > 0 && ((now - self.last_tick) as f64 - elapsed).abs() > 2.0
    }
    fn flush_detail(&mut self, now: i64) {
        if self.detail_queue.len() < 2 {
            self.detail_queue.push_back(self.current_detail(now));
            self.detail_ok = true;
            self.detail_omitted = 0;
            self.detail_gap_from = None;
        } else {
            self.detail_storage_ok = false;
            self.last_error = Some("Detail writer backpressure: checkpoint omitted".into());
            self.detail_omitted += self.detail.values().map(|r| r.counts.packets).sum::<u64>();
            self.detail_gap_from = Some(
                self.detail_gap_from
                    .unwrap_or(self.detail_from)
                    .min(self.detail_from),
            );
            self.detail_ok = false;
        }
        self.detail.clear();
        self.application_bytes = 0;
        self.detail_sequence += 1;
        self.detail_from = now;
    }
    async fn pump_detail(&mut self) {
        if self.detail_writer.as_ref().is_some_and(|w| w.is_finished()) {
            match self.detail_writer.take().unwrap().await {
                Ok(Ok(())) => {
                    self.detail_queue.pop_front();
                    self.detail_storage_ok = self.detail_gap_from.is_none()
                        && self.detail_queue.iter().all(|b| b.gap_from.is_none());
                }
                result => {
                    self.detail_storage_ok = false;
                    self.last_error = Some(format!("Detail checkpoint failed: {result:?}"));
                }
            }
        }
        if self.detail_writer.is_none()
            && let Some(batch) = self.detail_queue.front().cloned()
        {
            let db = self.db.clone();
            let retention = self.config.retention.clone();
            let cap = self.config.detail_row_limit;
            self.detail_writer = Some(tokio::spawn(async move {
                db.detail_checkpoint(batch, retention, cap).await
            }));
        }
    }
    async fn publish_live(&self, now: i64) {
        let mut batches: Vec<_> = self.detail_queue.iter().cloned().collect();
        batches.push(self.current_detail(now));
        *self.live_traffic.write().await = LiveTraffic { batches };
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
    async fn overview_totals_restore_without_inflating_live_rates_or_checkpoints() {
        let mut first = monitor(false).await;
        let now = unix_now();
        let observation = first.backend.poll().unwrap();
        let original_packets = observation.totals.packets;
        first.process(now, 1.0, observation).await;
        first
            .db
            .aggregate(first.bucket.clone(), first.config.retention.clone())
            .await
            .unwrap();
        first.bucket.totals = Totals::default();
        // Saving history in this process must not add it again to the overview.
        first.publish(Totals::default(), true).await;
        assert_eq!(first.snapshot.read().await.totals.packets, original_packets);

        let snapshot = Arc::new(RwLock::new(Snapshot::default()));
        let (updates, _) = broadcast::channel(4);
        let mut restarted = Monitor::new(first.config.clone(), first.db.clone(), snapshot, updates)
            .await
            .unwrap();
        {
            let restored = restarted.snapshot.read().await;
            assert_eq!(restored.totals.packets, original_packets);
            assert_eq!(restored.session_totals.packets, 0);
            assert_eq!(restored.rate.packets, 0);
        }
        for second in 1..=2 {
            let observation = restarted.backend.poll().unwrap();
            let expected_rate = observation.totals.packets - restarted.previous.packets;
            let expected_session = observation.totals.packets;
            restarted.process(now + second, 1.0, observation).await;
            let current = restarted.snapshot.read().await;
            assert_eq!(current.totals.packets, original_packets + expected_session);
            assert_eq!(current.session_totals.packets, expected_session);
            assert_eq!(current.rate.packets, expected_rate);
        }
        restarted
            .db
            .aggregate(restarted.bucket.clone(), restarted.config.retention.clone())
            .await
            .unwrap();
        assert_eq!(
            restarted.db.overview_totals().await.unwrap().packets,
            restarted.snapshot.read().await.totals.packets
        );
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
    async fn management_dns_updates_override_bans_and_publish_current_protection() {
        use crate::management::tests::{fixture, refresh};
        let mut m = monitor(false).await;
        m.config.management_allowlist = vec!["home.example".parse().unwrap()];
        m.management = fixture(&m.config, "home.example", &["192.0.2.24", "2001:db8::12"]);
        m.command(Action::Add {
            network: "192.0.2.0/24".parse().unwrap(),
            kind: RuleKind::Block,
            reason: "test covering ban".into(),
            seconds: None,
        })
        .await
        .unwrap();
        m.command(Action::Mode {
            automatic: true,
            blocking: true,
            acknowledged: true,
        })
        .await
        .unwrap();
        let mut o = m.backend.poll().unwrap();
        assert!(o.traffic.iter().all(|r| r.counts.dropped == 0));
        for source in &mut o.sources {
            source.syns = 20;
        }
        m.process(unix_now(), 1.0, o).await;
        assert!(!m.rules.iter().any(|r| {
            r.actor == "detector"
                && m.management
                    .networks
                    .iter()
                    .any(|n| n.contains(&r.network.addr()))
        }));
        {
            let snap = m.snapshot.read().await;
            assert_eq!(snap.management_allowlist, m.management.networks);
            assert!(snap.health.management_dns.ready);
            assert_eq!(snap.health.management_dns.hosts[0].hostname, "home.example");
        }
        refresh(&mut m.management, "home.example", Some(&["192.0.2.25"]));
        m.dirty = true;
        m.reconcile().await;
        let o = m.backend.poll().unwrap();
        let old = o
            .traffic
            .iter()
            .find(|r| r.source == "192.0.2.24".parse::<IpAddr>().unwrap())
            .unwrap();
        assert!(old.counts.dropped > 0);
        m.publish(Totals::default(), true).await;
        assert_eq!(
            m.snapshot.read().await.management_allowlist,
            vec!["192.0.2.25/32".parse().unwrap()]
        );
        assert!(
            m.rules
                .iter()
                .any(|r| r.network == "192.0.2.0/24".parse::<IpNet>().unwrap() && r.applied)
        );
    }

    #[tokio::test]
    async fn management_dns_failure_suspends_bans_and_recovers_without_mode_change() {
        use crate::management::tests::{fixture, refresh};
        let mut m = monitor(false).await;
        m.config.management_allowlist = vec!["home.example".parse().unwrap()];
        m.management = fixture(&m.config, "home.example", &[]);
        assert!(
            m.command(Action::Mode {
                automatic: true,
                blocking: true,
                acknowledged: true
            })
            .await
            .is_err()
        );
        refresh(&mut m.management, "home.example", Some(&["192.0.2.24"]));
        m.command(Action::Mode {
            automatic: true,
            blocking: true,
            acknowledged: true,
        })
        .await
        .unwrap();
        refresh(&mut m.management, "home.example", None);
        let o = m.backend.poll().unwrap();
        m.process(unix_now(), 1.0, o).await;
        assert!(m.automatic && m.blocking && m.rules.is_empty());
        assert!(m.recent.iter().any(|d| d.eligible));
        assert!(!m.snapshot.read().await.health.management_dns.ready);
        refresh(&mut m.management, "home.example", Some(&["192.0.2.24"]));
        let mut o = m.backend.poll().unwrap();
        // Use a new scan event: the earlier SYN detection is on cooldown.
        o.syns = (1..=30)
            .map(|port| ("198.51.100.9".parse().unwrap(), port))
            .collect();
        m.process(unix_now() + 1, 1.0, o).await;
        assert!(m.rules.iter().any(|r| r.actor == "detector"));
        assert!(m.snapshot.read().await.health.management_dns.ready);
    }

    #[tokio::test]
    async fn service_policies_respect_management_dns_and_suspend_on_lookup_failure() {
        use crate::management::tests::{fixture, refresh};
        use einblick_core::services::*;
        let mut m = monitor(false).await;
        m.config.management_allowlist = vec!["home.example".parse().unwrap()];
        m.management = fixture(&m.config, "home.example", &["192.0.2.24"]);
        m.command(Action::Mode {
            automatic: true,
            blocking: true,
            acknowledged: true,
        })
        .await
        .unwrap();
        let mut service =
            m.db.save_service(ssh_template(), true, unix_now())
                .await
                .unwrap();
        service.observe_only = false;
        service.policies[0].observe_only = false;
        service.policies[0].threshold = 1;
        service = m.db.save_service(service, false, unix_now()).await.unwrap();
        let mut hit = playground(
            &service,
            "ssh-journal",
            "Failed password for root from 192.0.2.24 port 44",
            unix_now(),
            1,
        )
        .unwrap()
        .decisions[0]
            .clone();
        m.command(Action::ServiceDecision {
            hit: Box::new(hit.clone()),
            complete: true,
        })
        .await
        .unwrap();
        assert_eq!(
            m.db.service_decisions(service.id).await.unwrap()[0].status,
            "allowlisted"
        );
        refresh(&mut m.management, "home.example", None);
        hit.source_ip = "192.0.2.40".parse().unwrap();
        m.command(Action::ServiceDecision {
            hit: Box::new(hit.clone()),
            complete: true,
        })
        .await
        .unwrap();
        assert_eq!(
            m.db.service_decisions(service.id).await.unwrap()[0].status,
            "health_suspended"
        );
        assert!(m.rules.is_empty());
        refresh(&mut m.management, "home.example", Some(&["192.0.2.24"]));
        m.command(Action::ServiceDecision {
            hit: Box::new(hit),
            complete: true,
        })
        .await
        .unwrap();
        assert_eq!(m.rules.len(), 1);
        assert!(m.rules[0].applied);
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
    #[tokio::test]
    async fn detail_map_loss_does_not_suspend_complete_detection_evidence() {
        let mut m = monitor(true).await;
        m.command(Action::Mode {
            automatic: true,
            blocking: true,
            acknowledged: true,
        })
        .await
        .unwrap();
        let mut o = m.backend.poll().unwrap();
        o.totals.port_misses = 7;
        o.totals.association_misses = 3;
        o.port_misses = 7;
        o.association_misses = 3;
        o.totals.map_full = 10;
        m.process(unix_now(), 1.0, o).await;
        let snapshot = m.snapshot.read().await;
        assert!(snapshot.health.detection_complete);
        assert!(!snapshot.health.detail_complete && !snapshot.health.telemetry_complete);
        assert!(m.rules.iter().any(|r| r.actor == "detector"));
    }

    #[tokio::test]
    async fn missing_application_collector_does_not_degrade_detection_or_traffic() {
        let mut m = monitor(true).await;
        m.applications = crate::applications::Reader::disabled(config::ApplicationConfig {
            enabled: true,
            ..config::ApplicationConfig::default()
        });
        let o = m.backend.poll().unwrap();
        m.process(unix_now(), 1.0, o).await;
        let snapshot = m.snapshot.read().await;
        assert!(snapshot.health.detection_complete && snapshot.health.detail_complete);
        assert!(m.detail.values().all(|r| {
            r.application_attribution
                .reasons
                .contains(&ApplicationReason::Waiting)
        }));
    }

    #[tokio::test]
    async fn later_attribution_is_merged_into_an_initially_unknown_destination() {
        let mut m = monitor(true).await;
        m.applications = crate::applications::Reader::disabled(config::ApplicationConfig {
            enabled: true,
            ..config::ApplicationConfig::default()
        });
        let now = unix_now();
        let mut first = m.backend.poll().unwrap();
        first.traffic.truncate(1);
        let key = first.traffic[0].key();
        first.traffic[0].first_seen = now;
        first.traffic[0].last_seen = now;
        let first_packets = first.traffic[0].counts.packets;
        m.process(now, 1.0, first).await;
        assert!(
            m.detail[&key]
                .application_attribution
                .applications
                .is_empty()
        );

        m.applications = crate::applications::Reader::disabled(config::ApplicationConfig {
            services: vec![config::ServiceLabel {
                name: "web".into(),
                destination: format!("{}/32", key.1).parse().unwrap(),
                protocol: key.3,
                port: key.4.unwrap(),
                interface: None,
            }],
            ..config::ApplicationConfig::default()
        });
        let mut later = m.backend.poll().unwrap();
        later.traffic.truncate(1);
        assert_eq!(later.traffic[0].key(), key);
        later.traffic[0].first_seen = now + 1;
        later.traffic[0].last_seen = now + 1;
        let later_packets = later.traffic[0].counts.packets;
        m.process(now + 1, 1.0, later).await;
        let row = &m.detail[&key];
        assert_eq!(row.counts.packets, first_packets + later_packets);
        assert_eq!((row.first_seen, row.last_seen), (now, now + 1));
        assert_eq!(row.application_attribution.applications.len(), 1);
        assert_eq!(row.application_attribution.applications[0].name, "web");
        assert_eq!(
            row.application_attribution.applications[0].observed_from,
            now + 1
        );
        assert_eq!(
            row.application_attribution.reasons,
            vec![ApplicationReason::Waiting]
        );
    }

    #[tokio::test]
    async fn application_budget_preserves_counts_and_recovers_after_checkpoint() {
        let mut m = monitor(true).await;
        m.config.applications.batch_evidence_bytes = 1; // force saturation in this regression
        m.applications = crate::applications::Reader::disabled(config::ApplicationConfig {
            services: vec![config::ServiceLabel {
                name: "web".into(),
                destination: "192.0.2.1/32".parse().unwrap(),
                protocol: 6,
                port: 443,
                interface: None,
            }],
            ..config::ApplicationConfig::default()
        });
        let now = unix_now();
        let o = m.backend.poll().unwrap();
        let expected = o.traffic.iter().map(|r| r.counts.packets).sum::<u64>();
        m.process(now, 1.0, o).await;
        assert_eq!(
            m.detail.values().map(|r| r.counts.packets).sum::<u64>(),
            expected
        );
        assert!(m.detail.values().any(|r| {
            r.application_attribution
                .reasons
                .contains(&ApplicationReason::Truncated)
        }));
        assert!(
            m.detail
                .values()
                .all(|r| r.application_attribution.applications.is_empty())
        );
        let o = m.backend.poll().unwrap();
        m.process(now + 1, 1.0, o).await;
        assert_eq!(m.application_bytes, 0);
        assert!(m.snapshot.read().await.health.detail_complete);
        m.flush_detail(now + 2);
        m.config.applications.batch_evidence_bytes = 8388608;
        let o = m.backend.poll().unwrap();
        m.process(now + 3, 1.0, o).await;
        assert!(
            m.detail
                .values()
                .any(|r| !r.application_attribution.applications.is_empty())
        );
    }
    #[tokio::test]
    async fn source_map_loss_still_suspends_bans() {
        let mut m = monitor(true).await;
        m.command(Action::Mode {
            automatic: true,
            blocking: true,
            acknowledged: true,
        })
        .await
        .unwrap();
        let mut o = m.backend.poll().unwrap();
        o.totals.source_misses = 1;
        o.totals.map_full = 1;
        m.process(unix_now(), 1.0, o).await;
        assert!(m.rules.is_empty());
        assert!(!m.detection_complete);
    }
    #[tokio::test]
    async fn recreated_source_counters_start_a_new_baseline() {
        let mut m = monitor(false).await;
        let o = m.backend.poll().unwrap();
        let source = o.sources[0].clone();
        m.process(unix_now(), 1.0, o).await;
        let mut o = m.backend.poll().unwrap();
        let fresh = o.sources.iter_mut().find(|s| s.ip == source.ip).unwrap();
        fresh.generation += 1;
        fresh.packets = 5;
        fresh.bytes = 500;
        fresh.syns = 2;
        m.process(unix_now() + 1, 1.0, o).await;
        assert_eq!(
            m.bucket
                .sources
                .iter()
                .find(|s| s.ip == source.ip)
                .unwrap()
                .packets,
            source.packets + 5
        );
    }
    #[tokio::test]
    async fn full_checkpoint_queue_carries_a_durable_gap_and_omitted_count() {
        let mut m = monitor(false).await;
        let now = m.detail_from;
        m.flush_detail(now + 10);
        m.flush_detail(now + 20);
        let o = m.backend.poll().unwrap();
        let packets = o.traffic.iter().map(|r| r.counts.packets).sum::<u64>();
        for row in o.traffic {
            m.detail.insert(row.key(), row);
        }
        m.flush_detail(now + 30);
        assert_eq!(m.detail_queue.len(), 2);
        assert!(m.detail.is_empty() && !m.detail_storage_ok);
        assert_eq!(m.detail_gap_from, Some(now + 20));
        m.detail_queue.pop_front();
        m.flush_detail(now + 40);
        let recovery = m.detail_queue.back().unwrap();
        assert_eq!(recovery.gap_from, Some(now + 20));
        assert_eq!(recovery.omitted, packets);
        assert!(!recovery.complete);
    }
    #[tokio::test]
    async fn service_enforcement_uses_global_safeguards_and_independent_rules() {
        use einblick_core::services::*;
        let mut m = monitor(true).await;
        let mut service =
            m.db.save_service(ssh_template(), true, unix_now())
                .await
                .unwrap();
        service.observe_only = false;
        service.policies[0].observe_only = false;
        service.policies[0].threshold = 1;
        service = m.db.save_service(service, false, unix_now()).await.unwrap();
        let hit = playground(
            &service,
            "ssh-journal",
            "Failed password for root from 192.0.2.40 port 44",
            unix_now(),
            1,
        )
        .unwrap()
        .decisions[0]
            .clone();
        m.command(Action::ServiceDecision {
            hit: Box::new(hit.clone()),
            complete: true,
        })
        .await
        .unwrap();
        assert!(m.rules.is_empty());
        assert_eq!(
            m.db.service_decisions(service.id).await.unwrap()[0].status,
            "global_observe"
        );
        m.command(Action::Mode {
            automatic: true,
            blocking: true,
            acknowledged: true,
        })
        .await
        .unwrap();
        m.command(Action::ServiceDecision {
            hit: Box::new(hit.clone()),
            complete: false,
        })
        .await
        .unwrap();
        assert!(m.rules.is_empty());
        let mut allowed = hit.clone();
        allowed.source_ip = "192.0.2.24".parse().unwrap();
        m.command(Action::ServiceDecision {
            hit: Box::new(allowed),
            complete: true,
        })
        .await
        .unwrap();
        assert!(m.rules.is_empty());
        m.command(Action::ServiceDecision {
            hit: Box::new(hit.clone()),
            complete: true,
        })
        .await
        .unwrap();
        assert_eq!(m.rules.len(), 1);
        assert!(m.rules[0].applied);
        let first = m.rules[0].id;
        let mut second = service.clone();
        second.id = 0;
        second.revision = 0;
        second = m.db.save_service(second, true, unix_now()).await.unwrap();
        second.observe_only = false;
        second = m.db.save_service(second, false, unix_now()).await.unwrap();
        let mut hit2 = hit.clone();
        hit2.service_id = second.id;
        hit2.revision = second.revision;
        m.command(Action::ServiceDecision {
            hit: Box::new(hit2),
            complete: true,
        })
        .await
        .unwrap();
        assert_eq!(m.rules.len(), 2);
        m.command(Action::Remove(first)).await.unwrap();
        assert!(
            m.rules
                .iter()
                .any(|r| r.id != first && r.active(unix_now()) && r.applied)
        );
        m.db.delete_service(service.id, unix_now()).await.unwrap();
        assert!(
            m.command(Action::ServiceDecision {
                hit: Box::new(hit),
                complete: true
            })
            .await
            .is_err()
        );
        m.command(Action::Emergency).await.unwrap();
        assert!(!m.blocking && !m.automatic);
    }
}
