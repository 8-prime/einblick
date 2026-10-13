use serde::{Deserialize, Serialize};
use std::net::IpAddr;

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct TrafficCounts {
    pub packets: u64,
    pub bytes: u64,
    pub passed: u64,
    pub dropped: u64,
    pub syns: u64,
    pub syn_acks: u64,
    pub resets: u64,
}
impl TrafficCounts {
    pub fn add(&mut self, other: &Self) {
        self.packets += other.packets;
        self.bytes += other.bytes;
        self.passed += other.passed;
        self.dropped += other.dropped;
        self.syns += other.syns;
        self.syn_acks += other.syn_acks;
        self.resets += other.resets;
    }
}
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct TrafficRecord {
    pub source: IpAddr,
    pub destination: IpAddr,
    pub interface: String,
    pub protocol: u8,
    pub port: Option<u16>,
    #[serde(flatten)]
    pub counts: TrafficCounts,
    pub first_seen: i64,
    pub last_seen: i64,
    pub source_ports: Vec<u16>,
    pub source_ports_truncated: bool,
    #[serde(default)]
    pub application_attribution: crate::ApplicationAttribution,
}
pub type TrafficKey = (IpAddr, IpAddr, String, u8, Option<u16>);
pub type TrafficCursor = (String, String, String, u8, i32);
impl TrafficRecord {
    pub fn key(&self) -> TrafficKey {
        (
            self.source,
            self.destination,
            self.interface.clone(),
            self.protocol,
            self.port,
        )
    }
    pub fn cursor(&self) -> TrafficCursor {
        (
            self.source.to_string(),
            self.destination.to_string(),
            self.interface.clone(),
            self.protocol,
            self.port.map_or(-1, i32::from),
        )
    }
    pub fn merge(&mut self, other: &Self) {
        self.application_attribution
            .merge(&other.application_attribution);
        self.counts.add(&other.counts);
        self.first_seen = self.first_seen.min(other.first_seen);
        self.last_seen = self.last_seen.max(other.last_seen);
        self.source_ports_truncated |= other.source_ports_truncated;
        for &port in &other.source_ports {
            if !self.source_ports.contains(&port) {
                if self.source_ports.len() < 8 {
                    self.source_ports.push(port);
                } else {
                    self.source_ports_truncated = true;
                }
            }
        }
        self.source_ports.sort_unstable();
    }
}
#[derive(Clone, Debug, Default)]
pub struct LiveTraffic {
    pub batches: Vec<DetailBatch>,
}
impl LiveTraffic {
    pub fn for_query(&self, q: &TrafficQuery) -> Self {
        self.for_query_matching(q, |_| true)
    }
    pub fn for_query_matching(
        &self,
        q: &TrafficQuery,
        mut matches_source: impl FnMut(IpAddr) -> bool,
    ) -> Self {
        let cursor = q.cursor.clone().unwrap_or_default();
        let mut batches = vec![];
        for batch in &self.batches {
            let mut selected = std::collections::BTreeMap::new();
            for row in batch
                .rows
                .iter()
                .filter(|r| q.matches(r) && matches_source(r.source))
            {
                let key = row.cursor();
                if key <= cursor {
                    continue;
                }
                selected.insert(key, row);
                if selected.len() > q.limit + 1 {
                    selected.pop_last();
                }
            }
            batches.push(DetailBatch {
                rows: selected.into_values().cloned().collect(),
                run: batch.run.clone(),
                sequence: batch.sequence,
                from: batch.from,
                to: batch.to,
                complete: batch.complete,
                omitted: batch.omitted,
                gap_from: batch.gap_from,
            });
        }
        Self { batches }
    }
}
#[derive(Clone, Debug)]
pub struct DetailBatch {
    pub run: String,
    pub sequence: u64,
    pub from: i64,
    pub to: i64,
    pub rows: Vec<TrafficRecord>,
    pub complete: bool,
    pub omitted: u64,
    pub gap_from: Option<i64>,
}
#[derive(Clone, Debug)]
pub struct TrafficQuery {
    pub ip: Option<IpAddr>,
    pub destination: Option<IpAddr>,
    pub interface: Option<String>,
    pub source_port: Option<u16>,
    pub resolution: String,
    pub from: i64,
    pub to: i64,
    pub protocol: Option<u8>,
    pub port: Option<u16>,
    pub cursor: Option<TrafficCursor>,
    pub limit: usize,
}
impl TrafficQuery {
    pub fn matches(&self, row: &TrafficRecord) -> bool {
        self.ip.is_none_or(|ip| row.source == ip)
            && self.destination.is_none_or(|ip| row.destination == ip)
            && self
                .interface
                .as_ref()
                .is_none_or(|name| &row.interface == name)
            && self
                .source_port
                .is_none_or(|port| row.source_ports.contains(&port))
            && self.protocol.is_none_or(|p| p == row.protocol)
            && self.port.is_none_or(|p| Some(p) == row.port)
    }
}
#[derive(Clone, Debug, Serialize)]
pub struct TrafficPage {
    pub ip_info: Option<crate::IpInfo>,
    pub rows: Vec<TrafficRecord>,
    pub next_cursor: Option<String>,
    pub capture_started: Option<i64>,
    pub attribution_started: Option<i64>,
    pub available_from: Option<i64>,
    pub available_to: Option<i64>,
    pub complete: bool,
    pub omitted: u64,
    pub stored_rows: usize,
    pub warnings: Vec<String>,
}
