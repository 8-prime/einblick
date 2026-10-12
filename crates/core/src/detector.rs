use crate::{Detection, config::Thresholds};
use std::{
    collections::{HashMap, VecDeque},
    net::IpAddr,
};

#[derive(Default)]
struct Window {
    samples: VecDeque<(i64, u64, u64)>,
    ports: HashMap<u16, (i64, VecDeque<i64>)>,
    cooldown: HashMap<&'static str, i64>,
    last: i64,
}
pub struct Detector {
    thresholds: Thresholds,
    windows: HashMap<IpAddr, Window>,
    capacity: usize,
    pub evidence_complete: bool,
}
impl Detector {
    pub fn new(thresholds: Thresholds, capacity: usize) -> Self {
        Self {
            thresholds,
            windows: HashMap::new(),
            capacity,
            evidence_complete: true,
        }
    }
    pub fn clear(&mut self) {
        self.windows.clear();
    }
    /// Evidence is accepted only for complete one-second observations.
    pub fn tick(
        &mut self,
        now: i64,
        rates: &[(IpAddr, u64, u64)],
        syns: &[(IpAddr, u16)],
        complete: bool,
    ) -> Vec<Detection> {
        self.evidence_complete = complete;
        if !complete {
            self.clear();
            return vec![];
        }
        self.windows.retain(|_, w| now - w.last <= 60);
        let mut overflow = false;
        for &(ip, packets, syn) in rates {
            if !self.windows.contains_key(&ip) && self.windows.len() >= self.capacity {
                overflow = true;
                break;
            }
            let w = self.windows.entry(ip).or_default();
            w.last = now;
            if w.samples.back().is_some_and(|(t, _, _)| *t == now) {
                continue;
            }
            w.samples.push_back((now, packets, syn));
            while w.samples.front().is_some_and(|(t, _, _)| *t <= now - 60) {
                w.samples.pop_front();
            }
            w.ports.retain(|_, (t, _)| *t > now - 60);
        }
        for &(ip, port) in syns {
            if !self.windows.contains_key(&ip) && self.windows.len() >= self.capacity {
                overflow = true;
                break;
            }
            let w = self.windows.entry(ip).or_default();
            w.last = now;
            if !w.ports.contains_key(&port) && w.ports.len() >= 1024 {
                overflow = true;
                break;
            }
            let (last, q) = w.ports.entry(port).or_default();
            *last = now;
            while q.front().is_some_and(|t| *t <= now - 60) {
                q.pop_front();
            }
            // Only keep evidence up to the configured threshold (bounded memory).
            if q.len() < self.thresholds.repeated_syns_60s {
                q.push_back(now);
            }
        }
        let evidence_count: usize = self
            .windows
            .values()
            .map(|w| w.ports.values().map(|(_, q)| q.len()).sum::<usize>())
            .sum();
        if overflow || evidence_count > 65536 {
            self.evidence_complete = false;
            self.clear();
            return vec![];
        }
        let mut out = Vec::new();
        for (&ip, w) in &mut self.windows {
            let syns: u64 = w
                .samples
                .iter()
                .filter(|(t, _, _)| *t > now - 10)
                .map(|(_, _, s)| s)
                .sum();
            let flood = w.samples.iter().rev().take(3).collect::<Vec<_>>();
            let sustained = flood.len() == 3
                && flood
                    .iter()
                    .enumerate()
                    .all(|(i, (t, p, _))| *t == now - i as i64 && *p >= self.thresholds.flood_pps);
            let repeated = w
                .ports
                .values()
                .map(|(_, q)| q.iter().filter(|t| **t > now - 60).count())
                .max()
                .unwrap_or(0);
            for (kind, hit, evidence, eligible) in [
                (
                    "port_scan",
                    w.ports.len() >= self.thresholds.scan_ports,
                    format!("{} distinct TCP ports in 60s", w.ports.len()),
                    true,
                ),
                (
                    "syn_flood",
                    syns >= self.thresholds.syns_10s,
                    format!("{syns} SYN attempts in 10s; includes retransmissions"),
                    true,
                ),
                (
                    "packet_flood",
                    sustained,
                    format!("at least {} packets/s for 3s", self.thresholds.flood_pps),
                    true,
                ),
                (
                    "repeated_attempts",
                    repeated >= self.thresholds.repeated_syns_60s,
                    format!("{repeated} SYNs to one port in 60s; includes retransmissions"),
                    self.thresholds.repeated_auto_ban,
                ),
            ] {
                if hit && w.cooldown.get(kind).is_none_or(|last| now - *last >= 60) {
                    w.cooldown.insert(kind, now);
                    out.push(Detection {
                        at: now,
                        ip,
                        kind: kind.into(),
                        evidence,
                        eligible,
                    });
                }
            }
        }
        out
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    fn ip() -> IpAddr {
        "192.0.2.1".parse().unwrap()
    }
    #[test]
    fn scan_deduplicates_retransmissions_and_expires() {
        let mut d = Detector::new(Thresholds::default(), 128);
        let syns = vec![(ip(), 22); 100];
        assert!(d.tick(1, &[(ip(), 100, 100)], &syns, true).is_empty());
        let syns = (1..=25).map(|p| (ip(), p)).collect::<Vec<_>>();
        assert!(
            d.tick(2, &[(ip(), 25, 25)], &syns, true)
                .iter()
                .any(|e| e.kind == "port_scan")
        );
        assert!(d.tick(63, &[(ip(), 1, 1)], &[(ip(), 22)], true).is_empty());
    }
    #[test]
    fn incomplete_evidence_clears_window() {
        let mut d = Detector::new(Thresholds::default(), 128);
        d.tick(1, &[(ip(), 900, 900)], &[], true);
        d.tick(2, &[], &[], false);
        assert!(d.tick(3, &[(ip(), 200, 200)], &[], true).is_empty());
    }
    #[test]
    fn flood_requires_consecutive_seconds_and_repeated_is_advisory() {
        let mut d = Detector::new(Thresholds::default(), 128);
        d.tick(1, &[(ip(), 20000, 0)], &[], true);
        d.tick(3, &[(ip(), 20000, 0)], &[], true);
        assert!(d.tick(4, &[(ip(), 20000, 0)], &[], true).is_empty());
        assert!(
            d.tick(5, &[(ip(), 20000, 0)], &vec![(ip(), 22); 300], true)
                .iter()
                .any(|e| e.kind == "packet_flood")
        );
        let mut d = Detector::new(Thresholds::default(), 128);
        assert!(
            !d.tick(1, &[(ip(), 300, 300)], &vec![(ip(), 22); 300], true)
                .iter()
                .find(|e| e.kind == "repeated_attempts")
                .unwrap()
                .eligible
        );
    }
}
