use einblick_core::{Aggregate, IpInfo, Totals};
use serde::Serialize;
use std::{collections::BTreeMap, net::IpAddr};

#[derive(Clone, Default, Serialize)]
pub struct Volume {
    pub packets: u64,
    pub bytes: u64,
}
impl Volume {
    fn add(&mut self, packets: u64, bytes: u64) {
        self.packets += packets;
        self.bytes += bytes;
    }
}
#[derive(Serialize)]
pub struct Ranking {
    pub key: String,
    pub label: String,
    #[serde(flatten)]
    pub volume: Volume,
}
#[derive(Serialize)]
pub struct Point {
    pub at: i64,
    pub packets: u64,
    pub bytes: u64,
    pub passed: u64,
    pub dropped: u64,
    pub complete: bool,
}
#[derive(Default, Serialize)]
pub struct Summary {
    pub from: i64,
    pub to: i64,
    pub totals: Totals,
    pub timeline: Vec<Point>,
    pub countries: Vec<Ranking>,
    pub networks: Vec<Ranking>,
    pub protocols: Vec<Ranking>,
    pub ports: Vec<Ranking>,
    pub country_mapped: Volume,
    pub source_tracked: Volume,
    pub incomplete_buckets: usize,
    pub missing_buckets: usize,
}

// Memory stays bounded by the selected range, country/ASN keys, and two fixed
// transport-port arrays. Raw hourly buckets are consumed on the read worker.
pub struct Builder {
    summary: Summary,
    countries: BTreeMap<String, Ranking>,
    networks: BTreeMap<String, Ranking>,
    protocols: [u64; 256],
    ports: Vec<u64>,
    no_port: u64,
    port_untracked: u64,
}
impl Builder {
    pub fn new(from: i64, to: i64) -> Self {
        Self {
            summary: Summary {
                from,
                to,
                ..Default::default()
            },
            countries: BTreeMap::new(),
            networks: BTreeMap::new(),
            protocols: [0; 256],
            ports: vec![0; 2 * 65536],
            no_port: 0,
            port_untracked: 0,
        }
    }
    pub fn add(&mut self, bucket: Aggregate, mut lookup: impl FnMut(IpAddr) -> Option<IpInfo>) {
        self.summary.totals.add(&bucket.totals);
        self.summary.incomplete_buckets += usize::from(!bucket.complete);
        self.summary.timeline.push(Point {
            at: bucket.at,
            packets: bucket.totals.packets,
            bytes: bucket.totals.bytes,
            passed: bucket.totals.passed,
            dropped: bucket.totals.dropped,
            complete: bucket.complete,
        });
        let mut tracked = Volume::default();
        for source in bucket.sources {
            let info = lookup(source.ip).unwrap_or_default();
            let (country_key, country_label) = match info.country_code {
                Some(code) => {
                    self.summary
                        .country_mapped
                        .add(source.packets, source.bytes);
                    (code.clone(), info.country.unwrap_or(code))
                }
                None => ("unknown".into(), "Country unavailable".into()),
            };
            add_rank(
                &mut self.countries,
                country_key,
                country_label,
                source.packets,
                source.bytes,
            );
            let (network_key, network_label) = match info.asn {
                Some(asn) => (
                    asn.to_string(),
                    format!(
                        "AS{asn} · {}",
                        info.organization
                            .unwrap_or_else(|| "Organization unavailable".into())
                    ),
                ),
                None => ("unknown".into(), "Network unavailable".into()),
            };
            add_rank(
                &mut self.networks,
                network_key,
                network_label,
                source.packets,
                source.bytes,
            );
            tracked.add(source.packets, source.bytes);
        }
        self.summary
            .source_tracked
            .add(tracked.packets, tracked.bytes);
        let untracked_packets = bucket.totals.packets.saturating_sub(tracked.packets);
        let untracked_bytes = bucket.totals.bytes.saturating_sub(tracked.bytes);
        for ranks in [&mut self.countries, &mut self.networks] {
            add_rank(
                ranks,
                "untracked".into(),
                "Other / untracked sources".into(),
                untracked_packets,
                untracked_bytes,
            );
        }
        let mut port_packets = 0;
        for port in bucket.ports {
            port_packets += port.packets;
            self.protocols[usize::from(port.protocol)] += port.packets;
            if port.port != 0 && matches!(port.protocol, 6 | 17) {
                let offset = if port.protocol == 17 { 65536 } else { 0 };
                self.ports[offset + usize::from(port.port)] += port.packets;
            } else {
                self.no_port += port.packets;
            }
        }
        self.port_untracked += bucket.totals.packets.saturating_sub(port_packets);
    }
    pub fn finish(mut self) -> Summary {
        let expected = (self.summary.to - self.summary.from) / 3600 + 1;
        self.summary.missing_buckets =
            (expected as usize).saturating_sub(self.summary.timeline.len());
        self.summary.countries = self.countries.into_values().collect();
        self.summary.networks = self.networks.into_values().collect();
        // Keep both packet and byte leaders; the frontend can switch metrics.
        compact(&mut self.summary.networks, 10);
        self.summary.protocols = self
            .protocols
            .into_iter()
            .enumerate()
            .filter(|(_, n)| *n > 0)
            .map(|(p, n)| Ranking {
                key: p.to_string(),
                label: protocol(p as u8),
                volume: Volume {
                    packets: n,
                    bytes: 0,
                },
            })
            .collect();
        self.summary.ports = self
            .ports
            .into_iter()
            .enumerate()
            .filter(|(_, n)| *n > 0)
            .map(|(index, n)| {
                let transport = if index >= 65536 { "UDP" } else { "TCP" };
                Ranking {
                    key: index.to_string(),
                    label: format!("{} / {transport}", index % 65536),
                    volume: Volume {
                        packets: n,
                        bytes: 0,
                    },
                }
            })
            .collect();
        compact(&mut self.summary.ports, 10);
        for (key, label, packets) in [
            ("none", "Unparsed / no destination port", self.no_port),
            (
                "untracked",
                "Other / untracked port detail",
                self.port_untracked,
            ),
        ] {
            if packets > 0 {
                self.summary.ports.push(Ranking {
                    key: key.into(),
                    label: label.into(),
                    volume: Volume { packets, bytes: 0 },
                });
            }
        }
        if self.port_untracked > 0 {
            self.summary.protocols.push(Ranking {
                key: "untracked".into(),
                label: "Other / untracked protocol detail".into(),
                volume: Volume {
                    packets: self.port_untracked,
                    bytes: 0,
                },
            });
        }
        self.summary
    }
}
fn add_rank(
    ranks: &mut BTreeMap<String, Ranking>,
    key: String,
    label: String,
    packets: u64,
    bytes: u64,
) {
    if packets == 0 && bytes == 0 {
        return;
    }
    ranks
        .entry(key.clone())
        .or_insert_with(|| Ranking {
            key,
            label,
            volume: Volume::default(),
        })
        .volume
        .add(packets, bytes);
}
fn compact(rows: &mut Vec<Ranking>, limit: usize) {
    rows.sort_by(|a, b| {
        b.volume
            .packets
            .cmp(&a.volume.packets)
            .then(a.key.cmp(&b.key))
    });
    let packet_leaders: Vec<_> = rows.iter().take(limit).map(|r| r.key.clone()).collect();
    rows.sort_by(|a, b| b.volume.bytes.cmp(&a.volume.bytes).then(a.key.cmp(&b.key)));
    let byte_leaders: Vec<_> = rows
        .iter()
        .filter(|r| r.volume.bytes > 0)
        .take(limit)
        .map(|r| r.key.clone())
        .collect();
    let mut rest = Volume::default();
    rows.retain(|row| {
        let keep = packet_leaders.contains(&row.key)
            || byte_leaders.contains(&row.key)
            || matches!(row.key.as_str(), "unknown" | "untracked");
        if !keep {
            rest.add(row.volume.packets, row.volume.bytes);
        }
        keep
    });
    if rest.packets > 0 || rest.bytes > 0 {
        rows.push(Ranking {
            key: "other".into(),
            label: "Other tracked groups".into(),
            volume: rest,
        });
    }
}
fn protocol(p: u8) -> String {
    match p {
        6 => "TCP".into(),
        17 => "UDP".into(),
        1 => "ICMP".into(),
        58 => "ICMPv6".into(),
        _ => format!("IP {p}"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use einblick_core::{Port, Source};
    fn bucket(at: i64, complete: bool) -> Aggregate {
        Aggregate {
            at,
            complete,
            totals: Totals {
                packets: 100,
                bytes: 1000,
                passed: 90,
                dropped: 10,
                ..Default::default()
            },
            sources: vec![
                Source {
                    ip: "8.8.8.8".parse().unwrap(),
                    packets: 60,
                    bytes: 800,
                    syns: 2,
                    generation: 0,
                    ip_info: None,
                },
                Source {
                    ip: "192.168.1.1".parse().unwrap(),
                    packets: 20,
                    bytes: 100,
                    syns: 0,
                    generation: 0,
                    ip_info: None,
                },
            ],
            ports: vec![
                Port {
                    protocol: 6,
                    port: 443,
                    packets: 70,
                },
                Port {
                    protocol: 17,
                    port: 443,
                    packets: 10,
                },
                Port {
                    protocol: 1,
                    port: 0,
                    packets: 5,
                },
            ],
        }
    }
    #[test]
    fn preserves_totals_unknowns_and_gaps_without_double_counting() {
        let mut builder = Builder::new(0, 7200);
        for (at, complete) in [(0, true), (7200, false)] {
            builder.add(bucket(at, complete), |ip| {
                (ip.to_string() == "8.8.8.8").then(|| IpInfo {
                    country_code: Some("US".into()),
                    country: Some("United States".into()),
                    asn: Some(15169),
                    organization: Some("Example network".into()),
                })
            });
        }
        let summary = builder.finish();
        assert_eq!(summary.totals.packets, 200);
        assert_eq!(summary.country_mapped.packets, 120);
        assert_eq!(summary.source_tracked.packets, 160);
        assert_eq!(summary.missing_buckets, 1);
        assert_eq!(summary.incomplete_buckets, 1);
        for ranks in [
            &summary.countries,
            &summary.networks,
            &summary.protocols,
            &summary.ports,
        ] {
            assert_eq!(ranks.iter().map(|r| r.volume.packets).sum::<u64>(), 200);
        }
        assert_eq!(
            summary
                .countries
                .iter()
                .map(|r| r.volume.bytes)
                .sum::<u64>(),
            2000
        );
        assert_eq!(
            summary
                .ports
                .iter()
                .find(|r| r.label == "443 / TCP")
                .unwrap()
                .volume
                .packets,
            140
        );
        assert_eq!(
            summary
                .ports
                .iter()
                .find(|r| r.label == "443 / UDP")
                .unwrap()
                .volume
                .packets,
            20
        );
    }
    #[test]
    fn compaction_keeps_both_metric_leaders_and_accounts_for_tail() {
        let mut ranks: Vec<_> = (0..40)
            .map(|i| Ranking {
                key: i.to_string(),
                label: i.to_string(),
                volume: Volume {
                    packets: 40 - i,
                    bytes: i,
                },
            })
            .collect();
        let packets: u64 = ranks.iter().map(|r| r.volume.packets).sum();
        let bytes: u64 = ranks.iter().map(|r| r.volume.bytes).sum();
        compact(&mut ranks, 10);
        assert!(ranks.iter().any(|r| r.key == "0"));
        assert!(ranks.iter().any(|r| r.key == "39"));
        assert_eq!(ranks.iter().map(|r| r.volume.packets).sum::<u64>(), packets);
        assert_eq!(ranks.iter().map(|r| r.volume.bytes).sum::<u64>(), bytes);
        assert!(ranks.len() <= 21);
    }
}
