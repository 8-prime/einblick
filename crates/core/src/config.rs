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
    pub management_allowlist: Vec<ManagementEntry>,
    pub management_dns_refresh_seconds: u64,
    pub management_dns_stale_seconds: u64,
    pub detection: Thresholds,
    pub retention: Retention,
    pub applications: ApplicationConfig,
    pub ip_enrichment: IpEnrichmentConfig,
    pub service_logs: ServiceLogConfig,
}

/// Management exemptions accept literal networks, individual IPs, or DNS names.
#[derive(Clone, Debug, PartialEq, Eq, Deserialize, Serialize)]
#[serde(try_from = "String", into = "String")]
pub enum ManagementEntry {
    Network(IpNet),
    Hostname(String),
}

impl std::str::FromStr for ManagementEntry {
    type Err = anyhow::Error;

    fn from_str(value: &str) -> Result<Self> {
        if let Ok(network) = value.parse::<IpNet>() {
            return Ok(Self::Network(network.trunc()));
        }
        if let Ok(ip) = value.parse::<IpAddr>() {
            return Ok(Self::Network(IpNet::from(ip)));
        }
        let hostname = value.strip_suffix('.').unwrap_or(value);
        ensure!(
            valid_management_hostname(hostname),
            "invalid management allowlist entry {value:?}; use an IP, CIDR, or fully qualified DNS hostname"
        );
        Ok(Self::Hostname(hostname.to_ascii_lowercase()))
    }
}

fn valid_management_hostname(hostname: &str) -> bool {
    hostname.len() <= 253
        && hostname.contains('.')
        && hostname
            .rsplit('.')
            .next()
            .is_some_and(|label| label.bytes().any(|c| c.is_ascii_alphabetic()))
        && hostname.split('.').all(|label| {
            !label.is_empty()
                && label.len() <= 63
                && !label.starts_with('-')
                && !label.ends_with('-')
                && label
                    .bytes()
                    .all(|c| c.is_ascii_alphanumeric() || c == b'-')
        })
}

impl TryFrom<String> for ManagementEntry {
    type Error = anyhow::Error;
    fn try_from(value: String) -> Result<Self> {
        value.parse()
    }
}

impl From<ManagementEntry> for String {
    fn from(value: ManagementEntry) -> Self {
        match value {
            ManagementEntry::Network(network) => network.to_string(),
            ManagementEntry::Hostname(hostname) => hostname,
        }
    }
}

#[derive(Clone, Debug, Default, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct ServiceLogConfig {
    /// Explicit read-only directories; no filesystem access is enabled by default.
    pub allowed_roots: Vec<String>,
    /// Explicit journal directories, passed as arguments to journalctl.
    pub journal_directory: String,
}
#[derive(Clone, Debug, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct IpEnrichmentConfig {
    pub enabled: bool,
    /// Empty uses an ip-enrichment directory beside the history database.
    pub directory: String,
    pub check_seconds: u64,
}
impl Default for IpEnrichmentConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            directory: String::new(),
            check_seconds: 86400,
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct ApplicationConfig {
    pub enabled: bool,
    pub proc_root: String,
    pub refresh_seconds: u64,
    pub stale_seconds: u64,
    /// Empty disables Docker API access. Only Unix sockets are supported.
    pub docker_socket: String,
    pub batch_evidence_bytes: usize,
    pub services: Vec<ServiceLabel>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ServiceLabel {
    pub name: String,
    pub destination: IpNet,
    pub protocol: u8,
    pub port: u16,
    pub interface: Option<String>,
}

impl Default for ApplicationConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            proc_root: "/host/proc".into(),
            refresh_seconds: 2,
            stale_seconds: 10,
            docker_socket: String::new(),
            batch_evidence_bytes: 8 * 1024 * 1024,
            services: vec![],
        }
    }
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
            management_dns_refresh_seconds: 60,
            management_dns_stale_seconds: 300,
            detection: Thresholds::default(),
            retention: Retention::default(),
            applications: ApplicationConfig::default(),
            ip_enrichment: IpEnrichmentConfig::default(),
            service_logs: ServiceLogConfig::default(),
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
            self.service_logs.allowed_roots.len() <= 16,
            "too many log roots"
        );
        for root in &self.service_logs.allowed_roots {
            let p = Path::new(root);
            ensure!(
                p.is_absolute()
                    && p.components().count() > 2
                    && root.len() <= 4096
                    && !p
                        .components()
                        .any(|c| matches!(c, std::path::Component::ParentDir)),
                "log roots must be explicit absolute subdirectories"
            );
        }
        let journal = &self.service_logs.journal_directory;
        ensure!(
            journal.is_empty()
                || (Path::new(journal).is_absolute()
                    && journal.len() <= 4096
                    && !Path::new(journal)
                        .components()
                        .any(|c| matches!(c, std::path::Component::ParentDir))),
            "invalid journal directory"
        );
        self.applications.validate()?;
        ensure!(
            (3600..=7 * 86400).contains(&self.ip_enrichment.check_seconds),
            "IP enrichment check_seconds must be between one hour and seven days"
        );
        ensure!(
            self.ip_enrichment.directory.len() <= 4096,
            "IP enrichment directory too long"
        );
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
        for entry in &self.management_allowlist {
            if let ManagementEntry::Hostname(hostname) = entry {
                ensure!(
                    valid_management_hostname(hostname),
                    "invalid management hostname"
                );
            }
        }
        ensure!(
            (10..=3600).contains(&self.management_dns_refresh_seconds)
                && self.management_dns_stale_seconds >= self.management_dns_refresh_seconds
                && self.management_dns_stale_seconds <= 86400,
            "management DNS refresh must be 10–3600 seconds; stale grace must be at least the refresh interval and at most one day"
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

impl ApplicationConfig {
    pub fn validate(&self) -> Result<()> {
        ensure!(
            (1..=60).contains(&self.refresh_seconds)
                && self.stale_seconds >= self.refresh_seconds * 2
                && self.stale_seconds <= 120,
            "invalid application refresh/expiry"
        );
        ensure!(
            Path::new(&self.proc_root).is_absolute() && self.proc_root.len() <= 256,
            "application proc_root must be an absolute path (at most 256 bytes)"
        );
        ensure!(
            self.docker_socket.is_empty()
                || (Path::new(&self.docker_socket).is_absolute() && self.docker_socket.len() < 108),
            "application docker_socket must be an absolute Unix socket path"
        );
        ensure!(
            self.services.len() <= 128,
            "application service label capacity exceeded"
        );
        ensure!(
            (262144..=32 * 1024 * 1024).contains(&self.batch_evidence_bytes),
            "application batch_evidence_bytes must be between 256 KiB and 32 MiB"
        );
        for service in &self.services {
            ensure!(
                !service.name.is_empty()
                    && service.name.len() <= crate::APPLICATION_TEXT_LIMIT
                    && !service.name.chars().any(char::is_control),
                "invalid application service name"
            );
            ensure!(
                matches!(service.protocol, 6 | 17),
                "service protocol must be TCP (6) or UDP (17)"
            );
            ensure!(
                service
                    .interface
                    .as_ref()
                    .is_none_or(|i| !i.is_empty() && i.len() < 16),
                "invalid application service interface"
            );
        }
        Ok(())
    }
}

#[cfg(test)]
mod management_tests {
    use super::*;

    #[test]
    fn management_entries_accept_cidrs_ips_and_normalized_hostnames() {
        let config: Config = toml::from_str(r#"
            mock = true
            management_allowlist = ["192.0.2.10/24", "2001:db8::1", "HOME.Example.", "p549b2893.dip0.t-ipconnect.de"]
        "#).unwrap();
        config.validate().unwrap();
        assert_eq!(
            serde_json::to_value(config.management_allowlist).unwrap(),
            serde_json::json!([
                "192.0.2.0/24",
                "2001:db8::1/128",
                "home.example",
                "p549b2893.dip0.t-ipconnect.de"
            ])
        );
        assert!(matches!(
            "192.0.2.1".parse::<ManagementEntry>().unwrap(),
            ManagementEntry::Network(_)
        ));
    }

    #[test]
    fn management_entries_reject_urls_ports_wildcards_and_malformed_names() {
        for invalid in [
            "",
            "localhost",
            "192.0.2.999",
            "192.0.2.1/33",
            "::1/129",
            "https://home.example",
            "home.example:443",
            "*.example.com",
            "home..example",
            "-home.example",
            "home-.example",
            "home_example.com",
            " home.example",
            "home.example..",
            "hôme.example",
        ] {
            assert!(
                invalid.parse::<ManagementEntry>().is_err(),
                "accepted {invalid:?}"
            );
            assert!(
                toml::from_str::<Config>(&format!("management_allowlist = [{invalid:?}]")).is_err()
            );
        }
        assert!(
            format!("{}.example", "x".repeat(64))
                .parse::<ManagementEntry>()
                .is_err()
        );
        assert!(
            format!(
                "{}.{}.{}.{}.example",
                "x".repeat(63),
                "x".repeat(63),
                "x".repeat(63),
                "x".repeat(63)
            )
            .parse::<ManagementEntry>()
            .is_err()
        );
    }

    #[test]
    fn management_dns_settings_have_bounded_refresh_and_grace() {
        let mut config = Config {
            mock: true,
            ..Config::default()
        };
        config.validate().unwrap();
        config.management_dns_refresh_seconds = 9;
        assert!(config.validate().is_err());
        config.management_dns_refresh_seconds = 60;
        config.management_dns_stale_seconds = 59;
        assert!(config.validate().is_err());
        config.management_dns_stale_seconds = 86401;
        assert!(config.validate().is_err());
    }
}
