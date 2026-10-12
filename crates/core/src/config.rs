use anyhow::{Result, ensure};
use ipnet::IpNet;
use serde::{Deserialize, Serialize};
use std::{
    net::{IpAddr, SocketAddr},
    path::Path,
};

#[derive(Clone, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct Config {
    pub bind: SocketAddr,
    pub public_origin: String,
    pub trusted_proxies: Vec<IpNet>,
    pub interfaces: Vec<String>,
    pub generic_fallback: bool,
    pub mock: bool,
    pub database: String,
    pub password_file: String,
    pub secure_cookies: bool,
    pub source_capacity: u32,
    pub port_capacity: u32,
    pub association_capacity: u32,
    pub detail_minute_capacity: usize,
    pub detail_row_limit: usize,
    pub ring_bytes: u32,
    pub management_allowlist: Vec<IpNet>,
    pub detection: Thresholds,
    pub retention: Retention,
}
#[derive(Clone, Deserialize, Serialize)]
#[serde(default, deny_unknown_fields)]
pub struct Thresholds {
    pub scan_ports: usize,
    pub syns_10s: u64,
    pub flood_pps: u64,
    pub repeated_syns_60s: usize,
    pub repeated_auto_ban: bool,
    pub ban_seconds: i64,
}
#[derive(Clone, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct Retention {
    pub minute_days: i64,
    pub hourly_days: i64,
    pub event_days: i64,
}
impl Default for Thresholds {
    fn default() -> Self {
        Self {
            scan_ports: 25,
            syns_10s: 1000,
            flood_pps: 20_000,
            repeated_syns_60s: 300,
            repeated_auto_ban: false,
            ban_seconds: 600,
        }
    }
}
impl Default for Retention {
    fn default() -> Self {
        Self {
            minute_days: 7,
            hourly_days: 90,
            event_days: 90,
        }
    }
}
impl Default for Config {
    fn default() -> Self {
        Self {
            bind: "127.0.0.1:9080".parse().unwrap(),
            public_origin: "https://einblick.example.com".into(),
            trusted_proxies: vec![],
            interfaces: vec![],
            generic_fallback: true,
            mock: false,
            database: "data/einblick.sqlite".into(),
            password_file: "secrets/admin-password".into(),
            secure_cookies: true,
            source_capacity: 4096,
            port_capacity: 4096,
            association_capacity: 4096,
            detail_minute_capacity: 16384,
            detail_row_limit: 1_000_000,
            ring_bytes: 1 << 20,
            management_allowlist: vec![],
            detection: Thresholds::default(),
            retention: Retention::default(),
        }
    }
}
impl Config {
    pub fn load(path: &Path) -> Result<Self> {
        let c: Self = toml::from_str(&std::fs::read_to_string(path)?)?;
        c.validate()?;
        Ok(c)
    }
    pub fn validate(&self) -> Result<()> {
        ensure!(
            self.mock || !self.interfaces.is_empty(),
            "configure at least one interface, or use mock=true"
        );
        ensure!(
            self.interfaces.len() <= 8
                && self
                    .interfaces
                    .iter()
                    .all(|s| !s.is_empty() && s.len() < 16),
            "invalid interfaces"
        );
        let unique: std::collections::HashSet<_> = self.interfaces.iter().collect();
        ensure!(unique.len() == self.interfaces.len(), "duplicate interface");
        ensure!(
            self.public_origin.starts_with("https://")
                || (self.mock && self.public_origin.starts_with("http://")),
            "HTTPS public_origin required outside mock mode"
        );
        let authority = self
            .public_origin
            .split_once("://")
            .map(|(_, rest)| rest)
            .unwrap_or("");
        ensure!(
            !authority.is_empty() && !authority.contains(['/', '?', '#', '@', ' ', '\t']),
            "public_origin must contain only scheme and authority"
        );
        ensure!(
            self.management_allowlist.len() <= 128,
            "management allowlist capacity exceeded"
        );
        ensure!(
            !self.public_origin.ends_with('/') && !self.public_origin.contains(['\r', '\n']),
            "public_origin must have no trailing slash or newline"
        );
        ensure!(
            self.secure_cookies || self.mock,
            "secure cookies required outside mock mode"
        );
        ensure!(
            (128..=32768).contains(&self.source_capacity)
                && (128..=8192).contains(&self.port_capacity),
            "map capacities out of range"
        );
        ensure!(
            (128..=16384).contains(&self.association_capacity)
                && (128..=65536).contains(&self.detail_minute_capacity)
                && (128..=10_000_000).contains(&self.detail_row_limit),
            "detail capacities out of range"
        );
        ensure!(
            self.ring_bytes.is_power_of_two()
                && (65536..=8 * 1024 * 1024).contains(&self.ring_bytes),
            "ring_bytes must be a power of two between 64 KiB and 8 MiB"
        );
        ensure!(
            self.detection.scan_ports >= 2
                && self.detection.scan_ports <= 1024
                && self.detection.syns_10s > 0
                && self.detection.flood_pps > 0
                && (1..=10000).contains(&self.detection.repeated_syns_60s)
                && self.detection.ban_seconds > 0
                && self.detection.ban_seconds <= 86400,
            "invalid detection thresholds"
        );
        ensure!(
            self.retention.minute_days > 0
                && self.retention.hourly_days >= self.retention.minute_days
                && self.retention.event_days > 0,
            "invalid retention"
        );
        Ok(())
    }
    pub fn trusted(&self, ip: IpAddr) -> bool {
        self.trusted_proxies.iter().any(|n| n.contains(&ip))
    }
}
