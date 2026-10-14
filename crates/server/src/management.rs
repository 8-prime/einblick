//! Resolve management hostnames outside the capture/control loop. Only resolved
//! host addresses reach the existing allowlist compiler and ban decisions.
use anyhow::{Context, Result, ensure};
use einblick_core::{Config, ManagementDnsHealth, ManagementDnsHost, config::ManagementEntry};
use futures_util::future::join_all;
use ipnet::IpNet;
use std::{
    collections::{BTreeMap, BTreeSet},
    net::IpAddr,
    time::{Duration, Instant},
};
use tokio::task::JoinHandle;

const MAX_NETWORKS: usize = 128;
const MAX_HOST_ADDRESSES: usize = 16;
const LOOKUP_TIMEOUT: Duration = Duration::from_secs(5);

type Resolution = (String, Result<Vec<IpNet>>);

#[derive(Clone)]
struct Host {
    health: ManagementDnsHost,
    success_at: Option<Instant>,
}

pub struct ManagementAllowlist {
    static_networks: BTreeSet<IpNet>,
    hosts: BTreeMap<String, Host>,
    pub networks: Vec<IpNet>,
    refresh: Duration,
    stale: Duration,
    next_refresh: Instant,
    pending: Option<JoinHandle<Vec<Resolution>>>,
}

impl ManagementAllowlist {
    fn from_config(config: &Config) -> Self {
        let mut static_networks = BTreeSet::new();
        let mut hosts = BTreeMap::new();
        for entry in &config.management_allowlist {
            match entry {
                ManagementEntry::Network(network) => {
                    static_networks.insert(network.trunc());
                }
                ManagementEntry::Hostname(hostname) => {
                    hosts.entry(hostname.clone()).or_insert_with(|| Host {
                        health: ManagementDnsHost {
                            hostname: hostname.clone(),
                            networks: vec![],
                            last_attempt: None,
                            last_success: None,
                            error: Some("Waiting for DNS resolution".into()),
                        },
                        success_at: None,
                    });
                }
            }
        }
        Self {
            networks: static_networks.iter().copied().collect(),
            static_networks,
            hosts,
            refresh: Duration::from_secs(config.management_dns_refresh_seconds),
            stale: Duration::from_secs(config.management_dns_stale_seconds),
            next_refresh: Instant::now(),
            pending: None,
        }
    }

    pub async fn new(config: &Config) -> Self {
        let mut state = Self::from_config(config);
        // Resolve before loading/attaching persisted blocking rules, so a
        // successful initial lookup already protects management at attachment.
        if !state.hosts.is_empty() {
            let results = resolve(state.hosts.keys().cloned().collect()).await;
            state.apply(results, einblick_core::unix_now(), Instant::now());
        }
        state.next_refresh = Instant::now() + state.refresh;
        state
    }

    pub fn ready(&self) -> bool {
        !self.networks.is_empty() && self.hosts.values().all(|h| h.health.error.is_none())
    }

    pub fn health(&self) -> ManagementDnsHealth {
        ManagementDnsHealth {
            ready: self.ready(),
            refresh_seconds: self.refresh.as_secs(),
            stale_seconds: self.stale.as_secs(),
            hosts: self.hosts.values().map(|h| h.health.clone()).collect(),
        }
    }

    /// Poll only a completed lookup task; DNS must never stall capture or an
    /// emergency-disable command. Return whether the kernel allowlist changed.
    pub async fn poll(&mut self) -> bool {
        let previous = self.networks.clone();
        if self.pending.as_ref().is_some_and(|task| task.is_finished()) {
            let results = match self.pending.take().unwrap().await {
                Ok(results) => results,
                Err(error) => self
                    .hosts
                    .keys()
                    .map(|name| {
                        (
                            name.clone(),
                            Err(anyhow::anyhow!("DNS worker failed: {error}")),
                        )
                    })
                    .collect(),
            };
            self.apply(results, einblick_core::unix_now(), Instant::now());
        }
        self.expire(Instant::now());
        self.rebuild();
        if self.pending.is_none() && !self.hosts.is_empty() && Instant::now() >= self.next_refresh {
            self.pending = Some(tokio::spawn(resolve(self.hosts.keys().cloned().collect())));
            self.next_refresh = Instant::now() + self.refresh;
        }
        previous != self.networks
    }

    fn apply(&mut self, results: Vec<Resolution>, wall_now: i64, now: Instant) {
        let previous = self.hosts.clone();
        for (name, result) in results {
            let Some(host) = self.hosts.get_mut(&name) else {
                continue;
            };
            host.health.last_attempt = Some(wall_now);
            match result {
                Ok(networks) if !networks.is_empty() && networks.len() <= MAX_HOST_ADDRESSES => {
                    host.health.networks = networks;
                    host.health.last_success = Some(wall_now);
                    host.health.error = None;
                    host.success_at = Some(now);
                }
                Ok(_) => host.health.error = Some("DNS must return 1–16 distinct addresses".into()),
                Err(error) => host.health.error = Some(format!("{error:#}")),
            }
        }
        self.expire(now);
        self.rebuild();
        if self.networks.len() > MAX_NETWORKS {
            // Reject the entire oversized refresh rather than silently protect
            // only part of a hostname's addresses or exceed the compiler budget.
            self.hosts = previous.clone();
            for host in self.hosts.values_mut() {
                host.health.last_attempt = Some(wall_now);
                host.health.error =
                    Some("Resolved management allowlist exceeds 128 networks".into());
            }
            self.expire(now);
            self.rebuild();
        }
        for (name, host) in &self.hosts {
            let old = &previous[name].health;
            if host.health.error != old.error
                && let Some(error) = &host.health.error
            {
                tracing::warn!(hostname = name, %error, "management DNS unavailable; new automatic bans suspended");
            }
            if host.health.networks != old.networks {
                tracing::info!(hostname = name, networks = ?host.health.networks, "management DNS addresses updated");
            }
        }
    }

    fn expire(&mut self, now: Instant) {
        for host in self.hosts.values_mut() {
            if !host.health.networks.is_empty()
                && host
                    .success_at
                    .is_some_and(|at| now.duration_since(at) >= self.stale)
            {
                host.health.networks.clear();
                host.health.error =
                    Some("DNS addresses expired; waiting for a successful refresh".into());
                tracing::warn!(
                    hostname = host.health.hostname,
                    "stale management DNS addresses removed"
                );
            }
        }
    }

    fn rebuild(&mut self) {
        let mut networks = self.static_networks.clone();
        for host in self.hosts.values() {
            networks.extend(&host.health.networks);
        }
        self.networks = networks.into_iter().collect();
    }
}

impl Drop for ManagementAllowlist {
    fn drop(&mut self) {
        if let Some(task) = &self.pending {
            task.abort();
        }
    }
}

async fn resolve(hostnames: Vec<String>) -> Vec<Resolution> {
    // Config bounds this batch to 128 names. Concurrent deadlines keep startup
    // bounded to one timeout even when more than one configured name fails.
    join_all(hostnames.into_iter().map(|name| async move {
        let result = async {
            // A trailing dot avoids applying the host's DNS search suffixes.
            let absolute = format!("{name}.");
            let addresses = tokio::time::timeout(
                LOOKUP_TIMEOUT,
                tokio::net::lookup_host((absolute.as_str(), 0)),
            )
            .await
            .context("management DNS lookup timed out")?
            .context("management DNS lookup failed")?;
            host_networks(addresses.map(|address| address.ip()))
        }
        .await;
        (name, result)
    }))
    .await
}

fn host_networks(addresses: impl Iterator<Item = IpAddr>) -> Result<Vec<IpNet>> {
    let mut networks = BTreeSet::new();
    for ip in addresses {
        networks.insert(IpNet::from(ip));
        ensure!(
            networks.len() <= MAX_HOST_ADDRESSES,
            "DNS returned more than 16 distinct addresses"
        );
    }
    ensure!(!networks.is_empty(), "DNS returned no A or AAAA addresses");
    Ok(networks.into_iter().collect())
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    pub fn fixture(config: &Config, hostname: &str, ips: &[&str]) -> ManagementAllowlist {
        let mut state = ManagementAllowlist::from_config(config);
        refresh(&mut state, hostname, Some(ips));
        state.next_refresh = Instant::now() + state.refresh;
        state
    }

    pub fn refresh(state: &mut ManagementAllowlist, hostname: &str, ips: Option<&[&str]>) {
        let result = match ips {
            Some(ips) => answer(hostname, ips),
            None => (hostname.into(), Err(anyhow::anyhow!("DNS unavailable"))),
        };
        state.apply(vec![result], einblick_core::unix_now(), Instant::now());
    }

    fn state(entries: &[&str]) -> ManagementAllowlist {
        ManagementAllowlist::from_config(&Config {
            management_allowlist: entries.iter().map(|s| s.parse().unwrap()).collect(),
            ..Config::default()
        })
    }

    fn answer(name: &str, ips: &[&str]) -> Resolution {
        (
            name.into(),
            host_networks(ips.iter().map(|ip| ip.parse().unwrap())),
        )
    }

    #[test]
    fn dns_rotation_replaces_hosts_and_preserves_static_overlapping_entries() {
        let mut state = state(&["192.0.2.1/32", "HOME.example.", "home.example"]);
        assert!(!state.ready());
        assert_eq!(state.hosts.len(), 1);
        let now = Instant::now();
        state.apply(
            vec![answer(
                "home.example",
                &["192.0.2.1", "2001:db8::1", "192.0.2.1"],
            )],
            100,
            now,
        );
        assert!(state.ready());
        assert_eq!(state.networks.len(), 2);
        assert!(
            state
                .networks
                .iter()
                .all(|n| n.prefix_len() == if n.addr().is_ipv4() { 32 } else { 128 })
        );
        state.apply(
            vec![answer("home.example", &["192.0.2.2"])],
            160,
            now + Duration::from_secs(60),
        );
        assert_eq!(
            state.networks,
            vec![
                "192.0.2.1/32".parse().unwrap(),
                "192.0.2.2/32".parse().unwrap()
            ]
        );
        assert_eq!(state.health().hosts[0].last_success, Some(160));
    }

    #[test]
    fn failed_refresh_keeps_bounded_grace_then_expires_and_recovers() {
        let mut state = state(&["198.51.100.0/24", "home.example"]);
        let now = Instant::now();
        state.apply(vec![answer("home.example", &["192.0.2.1"])], 100, now);
        state.apply(
            vec![("home.example".into(), Err(anyhow::anyhow!("NXDOMAIN")))],
            160,
            now + Duration::from_secs(60),
        );
        assert!(!state.ready());
        assert_eq!(state.networks.len(), 2);
        // Expiry uses monotonic time, independently of wall-clock adjustments.
        state.expire(now + Duration::from_secs(300));
        state.rebuild();
        assert_eq!(state.networks, vec!["198.51.100.0/24".parse().unwrap()]);
        state.apply(
            vec![answer("home.example", &["192.0.2.2"])],
            50,
            now + Duration::from_secs(301),
        );
        assert!(state.ready());
        assert_eq!(
            state.health().hosts[0].networks,
            vec!["192.0.2.2/32".parse().unwrap()]
        );
    }

    #[test]
    fn empty_and_oversized_answers_do_not_replace_working_addresses() {
        assert!(host_networks(std::iter::empty()).is_err());
        assert!(host_networks((1..=17).map(|n| IpAddr::from([192, 0, 2, n]))).is_err());
        let mut state = state(&["home.example"]);
        let now = Instant::now();
        state.apply(vec![answer("home.example", &["192.0.2.1"])], 100, now);
        state.apply(
            vec![answer("home.example", &[])],
            160,
            now + Duration::from_secs(60),
        );
        assert!(!state.ready());
        assert_eq!(state.networks, vec!["192.0.2.1/32".parse().unwrap()]);
    }

    #[test]
    fn aggregate_capacity_rejects_refresh_atomically() {
        let mut entries = (1..=128)
            .map(|n| format!("192.0.2.{}/32", n))
            .collect::<Vec<_>>();
        entries[127] = "home.example".into();
        let mut state = state(&entries.iter().map(String::as_str).collect::<Vec<_>>());
        state.apply(
            vec![answer("home.example", &["198.51.100.1", "198.51.100.2"])],
            100,
            Instant::now(),
        );
        assert_eq!(state.networks.len(), 127);
        assert!(!state.ready());
        assert!(
            state.health().hosts[0]
                .error
                .as_ref()
                .unwrap()
                .contains("128")
        );
    }

    #[tokio::test]
    async fn pending_dns_does_not_block_polling_and_completed_result_is_applied() {
        let mut state = state(&["home.example"]);
        state.next_refresh = Instant::now() + Duration::from_secs(60);
        let (send, receive) = tokio::sync::oneshot::channel();
        state.pending = Some(tokio::spawn(async move { receive.await.unwrap() }));
        assert!(
            !tokio::time::timeout(Duration::from_millis(100), state.poll())
                .await
                .unwrap()
        );
        send.send(vec![answer("home.example", &["192.0.2.1"])])
            .unwrap();
        while !state.pending.as_ref().unwrap().is_finished() {
            tokio::task::yield_now().await;
        }
        assert!(state.poll().await);
        assert!(state.ready());
    }
}
