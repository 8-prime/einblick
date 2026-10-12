use ipnet::IpNet;
use serde::{Deserialize, Serialize};
use std::net::IpAddr;

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct Totals {
    pub packets: u64,
    pub bytes: u64,
    pub passed: u64,
    pub dropped: u64,
    pub parse_limits: u64,
    pub event_loss: u64,
    pub map_full: u64,
    #[serde(default)]
    pub source_misses: u64,
    #[serde(default)]
    pub port_misses: u64,
    #[serde(default)]
    pub association_misses: u64,
}
impl Totals {
    pub fn delta(&self, old: &Self) -> Self {
        Self {
            packets: self.packets.saturating_sub(old.packets),
            bytes: self.bytes.saturating_sub(old.bytes),
            passed: self.passed.saturating_sub(old.passed),
            dropped: self.dropped.saturating_sub(old.dropped),
            parse_limits: self.parse_limits.saturating_sub(old.parse_limits),
            event_loss: self.event_loss.saturating_sub(old.event_loss),
            map_full: self.map_full.saturating_sub(old.map_full),
            source_misses: self.source_misses.saturating_sub(old.source_misses),
            port_misses: self.port_misses.saturating_sub(old.port_misses),
            association_misses: self
                .association_misses
                .saturating_sub(old.association_misses),
        }
    }
    pub fn add(&mut self, b: &Self) {
        self.packets += b.packets;
        self.bytes += b.bytes;
        self.passed += b.passed;
        self.dropped += b.dropped;
        self.parse_limits += b.parse_limits;
        self.event_loss += b.event_loss;
        self.map_full += b.map_full;
        self.source_misses += b.source_misses;
        self.port_misses += b.port_misses;
        self.association_misses += b.association_misses;
    }
}
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Source {
    pub ip: IpAddr,
    pub packets: u64,
    pub bytes: u64,
    pub syns: u64,
    #[serde(default)]
    pub generation: u64,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Port {
    pub protocol: u8,
    pub port: u16,
    pub packets: u64,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Detection {
    pub at: i64,
    pub ip: IpAddr,
    pub kind: String,
    pub evidence: String,
    pub eligible: bool,
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum RuleKind {
    Allow,
    Block,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Rule {
    pub id: i64,
    pub network: IpNet,
    pub kind: RuleKind,
    pub reason: String,
    pub actor: String,
    pub created: i64,
    pub expires: Option<i64>,
    pub enabled: bool,
    pub applied: bool,
    pub error: Option<String>,
}
impl Rule {
    pub fn active(&self, now: i64) -> bool {
        self.enabled && self.expires.is_none_or(|e| e > now)
    }
}
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct Health {
    pub backend: String,
    pub attachments: Vec<String>,
    pub telemetry_complete: bool,
    pub detection_complete: bool,
    pub detail_complete: bool,
    pub reasons: Vec<String>,
    pub maps: Vec<MapHealth>,
    pub storage_ok: bool,
    pub enforcement_ok: bool,
    pub last_error: Option<String>,
    pub last_tick: i64,
}
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct MapHealth {
    pub name: String,
    pub used: usize,
    pub capacity: usize,
}
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct Snapshot {
    pub at: i64,
    pub totals: Totals,
    pub rate: Totals,
    pub sources: Vec<Source>,
    pub ports: Vec<Port>,
    pub detections: Vec<Detection>,
    pub rules: Vec<Rule>,
    pub automatic: bool,
    pub blocking: bool,
    pub health: Health,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Aggregate {
    pub at: i64,
    pub totals: Totals,
    pub sources: Vec<Source>,
    pub ports: Vec<Port>,
    pub complete: bool,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Event {
    pub id: i64,
    pub at: i64,
    pub kind: String,
    pub detail: serde_json::Value,
}
