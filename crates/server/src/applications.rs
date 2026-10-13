//! Optional application discovery. The child scans host state; the monitor only
//! reads bounded, immutable snapshots and never performs proc or Docker I/O.
mod docker;
mod sockets;

use anyhow::{Context, Result, ensure};
use einblick_core::{config::ApplicationConfig, *};
use serde::{Deserialize, Serialize};
use std::{
    collections::{BTreeMap, BTreeSet},
    io::{Read, Write},
    net::IpAddr,
    path::Path,
    process::{Child, Command, Stdio},
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};
use tokio::sync::watch;

const FRAME_LIMIT: usize = 2 * 1024 * 1024;
const SOCKET_LIMIT: usize = 4096;
const PROCESS_LIMIT: usize = 16384;
const FD_LIMIT: usize = 131072;
const LOCAL_ADDRESS_LIMIT: usize = 4096;

#[derive(Clone, Debug, Serialize, Deserialize)]
struct Endpoint {
    address: IpAddr,
    port: u16,
    protocol: u8,
    interface: Option<String>,
    remote: Option<IpAddr>,
    remote_port: u16,
    inode: u32,
    cookie: u64,
    v6_only: Option<bool>,
    owners: Vec<ApplicationEvidence>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct PublishedEndpoint {
    address: IpAddr,
    port: u16,
    protocol: u8,
    application: ApplicationEvidence,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
struct Inventory {
    observed_at: i64,
    monotonic_ns: u64,
    available: bool,
    reasons: Vec<ApplicationReason>,
    local_addresses: Vec<IpAddr>,
    sockets: Vec<Endpoint>,
    published: Vec<PublishedEndpoint>,
    #[serde(skip)]
    socket_index: BTreeMap<(u8, u16), Vec<usize>>,
    #[serde(skip)]
    published_index: BTreeMap<(u8, u16), Vec<usize>>,
    #[serde(skip)]
    local_set: BTreeSet<IpAddr>,
}

#[derive(Clone, Default)]
struct CollectorState {
    inventory: Option<Inventory>,
    previous: Vec<Inventory>,
    exited: bool,
}

pub struct Collector {
    child: Option<Arc<Mutex<Child>>>,
    pub reader: Reader,
}

#[derive(Clone)]
pub struct Reader {
    state: watch::Receiver<CollectorState>,
    config: ApplicationConfig,
}

impl Reader {
    pub fn disabled(config: ApplicationConfig) -> Self {
        let (_, state) = watch::channel(CollectorState::default());
        Self { state, config }
    }

    pub fn health(&self) -> ApplicationHealth {
        let state = self.state.borrow();
        let mut health = ApplicationHealth {
            enabled: self.config.enabled,
            state: if self.config.services.is_empty() {
                "disabled"
            } else {
                "configured labels"
            }
            .into(),
            ..ApplicationHealth::default()
        };
        if !self.config.enabled {
            return health;
        }
        health.state = "waiting".into();
        if let Some(inventory) = &state.inventory {
            health.last_scan = Some(inventory.observed_at);
            health.sockets = inventory.sockets.len();
            health.reasons = inventory.reasons.clone();
            health.state = if inventory.available {
                "observing"
            } else {
                "unavailable"
            }
            .into();
            if stale(inventory, self.config.stale_seconds) {
                health.state = "stale".into();
                health.reasons.push(ApplicationReason::Stale);
            }
        }
        if state.exited {
            health.state = "collector exited; restart container".into();
            health.reasons.push(ApplicationReason::CollectorUnavailable);
        }
        health
    }

    pub fn enrich(&self, row: &mut TrafficRecord) {
        let mut attribution = ApplicationAttribution {
            applications: vec![],
            reasons: vec![],
        };
        let Some(port) = row.port.filter(|_| matches!(row.protocol, 6 | 17)) else {
            row.application_attribution =
                ApplicationAttribution::unknown(ApplicationReason::UnsupportedTransport);
            return;
        };
        // Most specific configured endpoint wins; equal-specificity labels are
        // intentionally retained as multiple candidates.
        let matching = self.config.services.iter().filter(|s| {
            s.protocol == row.protocol
                && s.port == port
                && s.destination.contains(&row.destination)
                && s.interface.as_ref().is_none_or(|i| i == &row.interface)
        });
        let score = |s: &einblick_core::config::ServiceLabel| {
            (s.destination.prefix_len(), s.interface.is_some())
        };
        let best = matching.clone().map(score).max();
        for service in matching.filter(|s| Some(score(s)) == best) {
            attribution.add(ApplicationEvidence {
                id: format!("configured:{}", service.name),
                name: service.name.clone(),
                method: ApplicationMethod::Configured,
                pid: None,
                process_start: None,
                executable: None,
                service: None,
                container_id: None,
                observed_from: row.first_seen,
                observed_to: row.last_seen,
            });
        }
        if !self.config.enabled {
            if attribution.applications.is_empty() {
                attribution.reason(ApplicationReason::Disabled);
            }
            row.application_attribution = attribution;
            return;
        }
        let state = self.state.borrow();
        let inventory = state
            .inventory
            .iter()
            .chain(state.previous.iter())
            .find(|i| i.observed_at <= row.last_seen && i.available)
            .or(state.inventory.as_ref());
        let problem = if state.exited {
            Some(ApplicationReason::CollectorUnavailable)
        } else if inventory.is_none() {
            Some(ApplicationReason::Waiting)
        } else if !inventory.unwrap().available {
            Some(ApplicationReason::CollectorUnavailable)
        } else if stale(inventory.unwrap(), self.config.stale_seconds) {
            Some(ApplicationReason::Stale)
        } else {
            None
        };
        if let Some(problem) = problem {
            attribution.reason(problem);
        } else if let Some(inventory) = inventory {
            for reason in &inventory.reasons {
                attribution.reason(*reason);
            }
            // Never infer an owner from an inventory taken entirely after this
            // traffic interval or from evidence older than its configured expiry.
            if inventory.observed_at > row.last_seen
                || inventory.observed_at + (self.config.stale_seconds as i64) < row.first_seen
            {
                attribution.reason(ApplicationReason::Stale);
            } else {
                let local = inventory.local_set.contains(&row.destination);
                for index in inventory
                    .socket_index
                    .get(&(row.protocol, port))
                    .into_iter()
                    .flatten()
                {
                    let endpoint = &inventory.sockets[*index];
                    if local
                        && endpoint.port == port
                        && endpoint.protocol == row.protocol
                        && endpoint
                            .interface
                            .as_ref()
                            .is_none_or(|i| i == &row.interface)
                        && endpoint.remote.is_none_or(|remote| remote == row.source)
                        && (endpoint.remote_port == 0
                            || row.source_ports.contains(&endpoint.remote_port))
                        && socket_address_matches(endpoint, row.destination)
                    {
                        for owner in &endpoint.owners {
                            if owner.observed_from <= row.last_seen
                                && owner.observed_to + (self.config.stale_seconds as i64)
                                    >= row.first_seen
                            {
                                attribution.add(owner.clone());
                            }
                        }
                    }
                }
                for index in inventory
                    .published_index
                    .get(&(row.protocol, port))
                    .into_iter()
                    .flatten()
                {
                    let endpoint = &inventory.published[*index];
                    if endpoint.port == port
                        && endpoint.protocol == row.protocol
                        && (endpoint.address == row.destination
                            || (local
                                && endpoint.address.is_unspecified()
                                && endpoint.address.is_ipv4() == row.destination.is_ipv4()))
                        && endpoint.application.observed_from <= row.last_seen
                        && endpoint.application.observed_to + (self.config.stale_seconds as i64)
                            >= row.first_seen
                    {
                        attribution.add(endpoint.application.clone());
                    }
                }
            }
            if attribution.applications.is_empty() {
                attribution.reason(ApplicationReason::NoMatchingSocket);
            }
        }
        row.application_attribution = attribution;
    }
}

fn socket_address_matches(endpoint: &Endpoint, destination: IpAddr) -> bool {
    if endpoint.address == destination {
        return true;
    }
    if endpoint.address.is_unspecified() && endpoint.address.is_ipv4() == destination.is_ipv4() {
        return true;
    }
    if let (IpAddr::V6(address), IpAddr::V4(destination)) = (endpoint.address, destination) {
        return address.to_ipv4_mapped() == Some(destination)
            || (address.is_unspecified() && endpoint.v6_only == Some(false));
    }
    false
}

fn monotonic_ns() -> u64 {
    let mut time = libc::timespec {
        tv_sec: 0,
        tv_nsec: 0,
    };
    // CLOCK_MONOTONIC is supported on the required Linux deployment.
    unsafe {
        libc::clock_gettime(libc::CLOCK_MONOTONIC, &mut time);
    }
    time.tv_sec as u64 * 1_000_000_000 + time.tv_nsec as u64
}

fn stale(inventory: &Inventory, seconds: u64) -> bool {
    monotonic_ns().saturating_sub(inventory.monotonic_ns) > seconds * 1_000_000_000
}

impl Collector {
    /// Called before runtime threads and secrets exist. The child inherits host
    /// inspection permissions, then the parent irrevocably clears them for its
    /// normal runtime (no-new-privileges prevents exec-based reacquisition).
    pub fn start(config: &ApplicationConfig) -> Result<Self> {
        config.validate()?;
        let (sender, state) = watch::channel(CollectorState::default());
        let reader = Reader {
            state,
            config: config.clone(),
        };
        if !config.enabled {
            drop_inspection_capabilities()?;
            return Ok(Self {
                child: None,
                reader,
            });
        }
        let child = Command::new(std::env::current_exe()?)
            .arg("--internal-application-collector")
            .arg(std::process::id().to_string())
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::inherit())
            .spawn();
        let collector = Self {
            child: child.ok().map(|child| Arc::new(Mutex::new(child))),
            reader,
        };
        drop_inspection_capabilities()?;
        let Some(child) = collector.child.clone() else {
            sender.send_replace(CollectorState {
                exited: true,
                ..CollectorState::default()
            });
            return Ok(collector);
        };
        let setup = (|| -> Result<_> {
            let mut process = child
                .lock()
                .map_err(|_| anyhow::anyhow!("collector process lock poisoned"))?;
            write_frame(
                &mut process.stdin.take().context("collector stdin")?,
                &serde_json::to_vec(config)?,
            )?;
            process.stdout.take().context("collector stdout")
        })();
        let mut stdout = match setup {
            Ok(stdout) => stdout,
            Err(error) => {
                eprintln!("Application discovery unavailable: {error}");
                sender.send_replace(CollectorState {
                    exited: true,
                    ..CollectorState::default()
                });
                if let Ok(mut process) = child.lock() {
                    let _ = process.kill();
                    let _ = process.wait();
                }
                return Ok(collector);
            }
        };
        let startup_sender = sender.clone();
        let reader_child = child.clone();
        let spawned = std::thread::Builder::new()
            .name("application-ipc".into())
            .spawn(move || {
                loop {
                    let result = read_frame(&mut stdout).and_then(|data| {
                        let mut inventory: Inventory = serde_json::from_slice(&data)?;
                        inventory.validate()?;
                        inventory.index();
                        Ok(inventory)
                    });
                    match result {
                        Ok(inventory) => {
                            let old = sender.borrow().clone();
                            let previous = old
                                .inventory
                                .into_iter()
                                .chain(old.previous)
                                .filter(|i| {
                                    inventory.monotonic_ns.saturating_sub(i.monotonic_ns)
                                        <= 120_000_000_000
                                })
                                .take(2)
                                .collect();
                            sender.send_replace(CollectorState {
                                inventory: Some(inventory),
                                previous,
                                exited: false,
                            });
                        }
                        Err(_) => {
                            let mut old = sender.borrow().clone();
                            old.exited = true;
                            if let Ok(mut process) = reader_child.lock() {
                                let _ = process.kill();
                                let _ = process.wait();
                            }
                            sender.send_replace(old);
                            break;
                        }
                    }
                }
            });
        if let Err(error) = spawned {
            eprintln!("Application discovery unavailable: {error}");
            startup_sender.send_replace(CollectorState {
                exited: true,
                ..CollectorState::default()
            });
            if let Ok(mut process) = child.lock() {
                let _ = process.kill();
                let _ = process.wait();
            }
        }
        Ok(collector)
    }
}

impl Drop for Collector {
    fn drop(&mut self) {
        if let Some(child) = &mut self.child
            && let Ok(mut process) = child.lock()
        {
            let _ = process.kill();
            let _ = process.wait();
        }
    }
}

pub fn run_child(parent: u32) -> Result<()> {
    ensure!(
        unsafe { libc::prctl(libc::PR_SET_PDEATHSIG, libc::SIGKILL, 0, 0, 0) } == 0,
        "set collector parent-death signal"
    );
    ensure!(
        unsafe { libc::getppid() } as u32 == parent,
        "collector parent exited"
    );
    retain_inspection_capabilities()?;
    let config: ApplicationConfig = serde_json::from_slice(&read_frame(&mut std::io::stdin())?)?;
    config.validate()?;
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?;
    let mut stdout = std::io::stdout().lock();
    loop {
        let started = Instant::now();
        let mut inventory = discover(&config);
        if !config.docker_socket.is_empty() {
            match runtime.block_on(docker::discover(&config.docker_socket)) {
                Ok(published) => inventory.published = published,
                Err(_) => inventory.reasons.push(ApplicationReason::DockerUnavailable),
            }
        }
        if let Err(error) = inventory.validate() {
            eprintln!("application collector rejected snapshot: {error}");
            inventory = Inventory {
                observed_at: unix_now(),
                monotonic_ns: monotonic_ns(),
                reasons: vec![ApplicationReason::ScanLimit],
                ..Inventory::default()
            };
        }
        let mut bytes = serde_json::to_vec(&inventory)?;
        // Saturation must yield partial evidence, never exit the collector or
        // block the monitor. Halving bounds serialization work to a few passes.
        while bytes.len() > FRAME_LIMIT {
            if !inventory.reasons.contains(&ApplicationReason::ScanLimit) {
                inventory.reasons.push(ApplicationReason::ScanLimit);
            }
            if inventory.sockets.len() > inventory.published.len() {
                inventory.sockets.truncate(inventory.sockets.len() / 2);
            } else {
                inventory.published.truncate(inventory.published.len() / 2);
            }
            bytes = serde_json::to_vec(&inventory)?;
        }
        write_frame(&mut stdout, &bytes)?;
        std::thread::sleep(
            Duration::from_secs(config.refresh_seconds).saturating_sub(started.elapsed()),
        );
    }
}

fn read_frame(reader: &mut impl Read) -> Result<Vec<u8>> {
    let mut length = [0; 4];
    reader.read_exact(&mut length)?;
    let length = u32::from_be_bytes(length) as usize;
    ensure!(length <= FRAME_LIMIT, "collector frame exceeds limit");
    let mut data = vec![0; length];
    reader.read_exact(&mut data)?;
    Ok(data)
}

fn write_frame(writer: &mut impl Write, data: &[u8]) -> Result<()> {
    ensure!(data.len() <= FRAME_LIMIT, "collector frame exceeds limit");
    writer.write_all(&(data.len() as u32).to_be_bytes())?;
    writer.write_all(data)?;
    writer.flush()?;
    Ok(())
}

impl Inventory {
    fn index(&mut self) {
        self.socket_index.clear();
        self.published_index.clear();
        for (index, endpoint) in self.sockets.iter().enumerate() {
            self.socket_index
                .entry((endpoint.protocol, endpoint.port))
                .or_default()
                .push(index);
        }
        for (index, endpoint) in self.published.iter().enumerate() {
            self.published_index
                .entry((endpoint.protocol, endpoint.port))
                .or_default()
                .push(index);
        }
        self.local_set = self.local_addresses.iter().copied().collect();
    }
    fn validate(&self) -> Result<()> {
        ensure!(
            self.sockets.len() <= SOCKET_LIMIT
                && self.published.len() <= SOCKET_LIMIT
                && self.local_addresses.len() <= LOCAL_ADDRESS_LIMIT
                && self.reasons.len() <= 14,
            "collector inventory exceeds capacity"
        );
        for endpoint in &self.sockets {
            ensure!(
                endpoint.owners.len() <= APPLICATION_LIMIT
                    && endpoint.interface.as_ref().is_none_or(|i| i.len() < 16),
                "invalid socket metadata"
            );
            for owner in &endpoint.owners {
                validate_evidence(owner)?;
            }
        }
        for endpoint in &self.published {
            validate_evidence(&endpoint.application)?;
        }
        Ok(())
    }
}

fn validate_evidence(e: &ApplicationEvidence) -> Result<()> {
    ensure!(
        e.id.len() <= 256
            && e.name.len() <= APPLICATION_TEXT_LIMIT
            && [&e.executable, &e.service, &e.container_id]
                .into_iter()
                .all(|v| v.as_ref().is_none_or(|s| s.len() <= APPLICATION_TEXT_LIMIT))
            && e.observed_from <= e.observed_to,
        "invalid application metadata"
    );
    Ok(())
}

fn read_small(path: impl AsRef<Path>) -> std::io::Result<String> {
    let mut text = String::new();
    std::fs::File::open(path)?
        .take(4097)
        .read_to_string(&mut text)?;
    if text.len() > 4096 {
        return Err(std::io::Error::other("proc metadata exceeds limit"));
    }
    Ok(text)
}

fn process_start(stat: &str) -> Option<u64> {
    stat.rsplit_once(") ")?
        .1
        .split_whitespace()
        .nth(19)?
        .parse()
        .ok()
}

fn discover(config: &ApplicationConfig) -> Inventory {
    let root = Path::new(&config.proc_root);
    let started = Instant::now();
    let observed_at = unix_now();
    let mut inventory = Inventory {
        observed_at,
        monotonic_ns: monotonic_ns(),
        ..Inventory::default()
    };
    let Ok(boot) = read_small(root.join("sys/kernel/random/boot_id")) else {
        inventory
            .reasons
            .push(ApplicationReason::CollectorUnavailable);
        return inventory;
    };
    let Ok(processes) = std::fs::read_dir(root) else {
        inventory.reasons.push(ApplicationReason::PermissionDenied);
        return inventory;
    };
    let Ok(namespace) = std::fs::read_link("/proc/self/ns/net") else {
        return inventory;
    };
    let (endpoints, reasons, available) = sockets::discover();
    inventory.sockets = endpoints;
    inventory.reasons = reasons;
    inventory.available = available;
    inventory.local_addresses = sockets::local_addresses();
    if inventory.local_addresses.len() == LOCAL_ADDRESS_LIMIT {
        inventory.reasons.push(ApplicationReason::ScanLimit);
    }
    let mut by_inode = BTreeMap::<u32, Vec<usize>>::new();
    for (index, endpoint) in inventory.sockets.iter().enumerate() {
        by_inode.entry(endpoint.inode).or_default().push(index);
    }
    let mut process_count = 0;
    let mut fd_count = 0;
    let mut denied = false;
    let mut limited = false;
    for entry in processes {
        let Ok(entry) = entry else {
            continue;
        };
        let Some(pid) = entry
            .file_name()
            .to_str()
            .and_then(|p| p.parse::<u32>().ok())
        else {
            continue;
        };
        process_count += 1;
        if process_count > PROCESS_LIMIT || started.elapsed() > Duration::from_millis(1500) {
            limited = true;
            break;
        }
        let dir = entry.path();
        match std::fs::read_link(dir.join("ns/net")) {
            Ok(net) if net == namespace => {}
            Err(error) if error.kind() == std::io::ErrorKind::PermissionDenied => {
                denied = true;
                continue;
            }
            _ => continue,
        }
        let start = read_small(dir.join("stat"))
            .ok()
            .and_then(|s| process_start(&s));
        let Some(start) = start else {
            continue;
        };
        let descriptors = match std::fs::read_dir(dir.join("fd")) {
            Ok(fd) => fd,
            Err(error) => {
                denied |= error.kind() == std::io::ErrorKind::PermissionDenied;
                continue;
            }
        };
        let mut inodes = BTreeSet::new();
        for fd in descriptors {
            fd_count += 1;
            if fd_count > FD_LIMIT || started.elapsed() > Duration::from_millis(1500) {
                limited = true;
                break;
            }
            let Ok(fd) = fd else {
                continue;
            };
            match std::fs::read_link(fd.path()) {
                Ok(link) => {
                    let link = link.to_string_lossy();
                    if let Some(inode) = link
                        .strip_prefix("socket:[")
                        .and_then(|s| s.strip_suffix(']'))
                        .and_then(|s| s.parse::<u32>().ok())
                        && by_inode.contains_key(&inode)
                    {
                        inodes.insert(inode);
                    }
                }
                Err(error) => denied |= error.kind() == std::io::ErrorKind::PermissionDenied,
            }
        }
        if !inodes.is_empty()
            && read_small(dir.join("stat"))
                .ok()
                .and_then(|s| process_start(&s))
                == Some(start)
        {
            let name = read_small(dir.join("comm"))
                .map(|s| application_text(s.trim()))
                .unwrap_or_else(|_| format!("PID {pid}"));
            let executable = std::fs::read_link(dir.join("exe")).ok().and_then(|p| {
                p.file_name()
                    .map(|n| application_text(&n.to_string_lossy()))
            });
            let cgroup = read_small(dir.join("cgroup")).unwrap_or_default();
            let service = cgroup
                .lines()
                .flat_map(|line| line.split('/'))
                .find(|s| s.ends_with(".service"))
                .map(application_text);
            let container_id = cgroup
                .lines()
                .flat_map(|line| line.split('/'))
                .find_map(|s| {
                    let id = s
                        .strip_prefix("docker-")
                        .and_then(|s| s.strip_suffix(".scope"))
                        .unwrap_or(s);
                    (id.len() == 64 && id.bytes().all(|c| c.is_ascii_hexdigit()))
                        .then(|| id.to_owned())
                });
            let seen = unix_now();
            let owner = ApplicationEvidence {
                id: format!("process:{}:{pid}:{start}", application_text(boot.trim())),
                name,
                method: ApplicationMethod::SocketOwner,
                pid: Some(pid),
                process_start: Some(start),
                executable,
                service,
                container_id,
                observed_from: seen,
                observed_to: seen,
            };
            for inode in inodes {
                for index in &by_inode[&inode] {
                    let endpoint = &mut inventory.sockets[*index];
                    if endpoint.owners.len() < APPLICATION_LIMIT {
                        endpoint.owners.push(owner.clone());
                    } else {
                        limited = true;
                    }
                }
            }
        }
        if fd_count > FD_LIMIT {
            break;
        }
    }
    if denied {
        inventory.reasons.push(ApplicationReason::PermissionDenied);
    }
    if limited {
        inventory.reasons.push(ApplicationReason::ScanLimit);
    }
    inventory.reasons.sort();
    inventory.reasons.dedup();
    inventory
}

#[repr(C)]
struct CapabilityHeader {
    version: u32,
    pid: i32,
}
#[repr(C)]
#[derive(Clone, Copy, Default)]
struct CapabilityData {
    effective: u32,
    permitted: u32,
    inheritable: u32,
}

fn capabilities(only_inspection: bool) -> Result<()> {
    const INSPECTION: u64 = (1 << 19) | (1 << 2); // CAP_SYS_PTRACE, CAP_DAC_READ_SEARCH
    let mut header = CapabilityHeader {
        version: 0x20080522,
        pid: 0,
    };
    let mut data = [CapabilityData::default(); 2];
    let result = unsafe { libc::syscall(libc::SYS_capget, &mut header, data.as_mut_ptr()) };
    ensure!(
        result == 0,
        "read process capabilities: {}",
        std::io::Error::last_os_error()
    );
    for (index, data) in data.iter_mut().enumerate() {
        let mask = (INSPECTION >> (index * 32)) as u32;
        let keep = if only_inspection { mask } else { !mask };
        data.effective &= keep;
        data.permitted &= keep;
        data.inheritable &= keep;
    }
    let result = unsafe { libc::syscall(libc::SYS_capset, &header, data.as_ptr()) };
    ensure!(
        result == 0,
        "drop process capabilities: {}",
        std::io::Error::last_os_error()
    );
    ensure!(
        unsafe { libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) } == 0,
        "set no-new-privileges"
    );
    ensure!(
        unsafe {
            libc::prctl(
                libc::PR_CAP_AMBIENT,
                libc::PR_CAP_AMBIENT_CLEAR_ALL,
                0,
                0,
                0,
            )
        } == 0,
        "clear ambient capabilities"
    );
    Ok(())
}

pub fn drop_inspection_capabilities() -> Result<()> {
    capabilities(false)
}
fn retain_inspection_capabilities() -> Result<()> {
    capabilities(true)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn traffic(destination: &str, port: u16) -> TrafficRecord {
        TrafficRecord {
            source: "198.51.100.1".parse().unwrap(),
            destination: destination.parse().unwrap(),
            interface: "eth0".into(),
            protocol: 6,
            port: Some(port),
            counts: TrafficCounts {
                packets: 10,
                ..TrafficCounts::default()
            },
            first_seen: 100,
            last_seen: 101,
            source_ports: vec![45000],
            source_ports_truncated: false,
            application_attribution: ApplicationAttribution::default(),
        }
    }

    fn owner(name: &str, pid: u32) -> ApplicationEvidence {
        ApplicationEvidence {
            id: format!("process:{pid}:123"),
            name: name.into(),
            method: ApplicationMethod::SocketOwner,
            pid: Some(pid),
            process_start: Some(123),
            executable: None,
            service: None,
            container_id: None,
            observed_from: 100,
            observed_to: 100,
        }
    }

    fn reader(mut inventory: Inventory) -> Reader {
        inventory.available = true;
        inventory.observed_at = 100;
        inventory.monotonic_ns = monotonic_ns();
        inventory.index();
        let (_, state) = watch::channel(CollectorState {
            inventory: Some(inventory),
            exited: false,
            ..CollectorState::default()
        });
        Reader {
            state,
            config: ApplicationConfig {
                enabled: true,
                ..ApplicationConfig::default()
            },
        }
    }

    #[test]
    fn wildcard_listener_only_matches_local_destinations_and_preserves_counts() {
        let reader = reader(Inventory {
            local_addresses: vec!["192.0.2.1".parse().unwrap()],
            sockets: vec![Endpoint {
                address: "0.0.0.0".parse().unwrap(),
                port: 443,
                protocol: 6,
                interface: None,
                remote: None,
                remote_port: 0,
                inode: 1,
                cookie: 2,
                v6_only: None,
                owners: vec![owner("nginx", 1), owner("worker", 2)],
            }],
            ..Inventory::default()
        });
        let mut local = traffic("192.0.2.1", 443);
        reader.enrich(&mut local);
        assert_eq!(local.application_attribution.applications.len(), 2);
        assert_eq!(local.counts.packets, 10);
        let mut forwarded = traffic("172.18.0.2", 443);
        reader.enrich(&mut forwarded);
        assert!(forwarded.application_attribution.applications.is_empty());
        assert!(
            forwarded
                .application_attribution
                .reasons
                .contains(&ApplicationReason::NoMatchingSocket)
        );
    }

    #[test]
    fn stale_exited_and_future_inventory_never_relabels_traffic() {
        let mut reader = reader(Inventory::default());
        let mut row = traffic("192.0.2.1", 443);
        let (sender, state) = watch::channel(CollectorState {
            inventory: Some(Inventory {
                available: true,
                observed_at: 102,
                monotonic_ns: monotonic_ns(),
                ..Inventory::default()
            }),
            exited: false,
            ..CollectorState::default()
        });
        reader.state = state;
        reader.enrich(&mut row);
        assert!(
            row.application_attribution
                .reasons
                .contains(&ApplicationReason::Stale)
        );
        sender.send_replace(CollectorState {
            inventory: Some(Inventory {
                available: true,
                observed_at: 100,
                monotonic_ns: monotonic_ns().saturating_sub(20_000_000_000),
                ..Inventory::default()
            }),
            exited: false,
            ..CollectorState::default()
        });
        reader.enrich(&mut row);
        assert!(
            row.application_attribution
                .reasons
                .contains(&ApplicationReason::Stale)
        );
        sender.send_replace(CollectorState {
            exited: true,
            ..CollectorState::default()
        });
        reader.enrich(&mut row);
        assert!(
            row.application_attribution
                .reasons
                .contains(&ApplicationReason::CollectorUnavailable)
        );
    }

    #[test]
    fn configured_labels_choose_specific_scope_and_work_without_host_access() {
        use einblick_core::config::ServiceLabel;
        let config = ApplicationConfig {
            services: vec![
                ServiceLabel {
                    name: "general".into(),
                    destination: "192.0.2.0/24".parse().unwrap(),
                    protocol: 6,
                    port: 443,
                    interface: None,
                },
                ServiceLabel {
                    name: "web".into(),
                    destination: "192.0.2.1/32".parse().unwrap(),
                    protocol: 6,
                    port: 443,
                    interface: Some("eth0".into()),
                },
            ],
            ..ApplicationConfig::default()
        };
        let mut row = traffic("192.0.2.1", 443);
        Reader::disabled(config).enrich(&mut row);
        assert_eq!(row.application_attribution.applications[0].name, "web");
        assert_eq!(row.application_attribution.applications.len(), 1);
        assert_eq!(
            row.application_attribution.applications[0].method,
            ApplicationMethod::Configured
        );
        assert!(row.application_attribution.reasons.is_empty());
    }

    #[test]
    fn ipc_rejects_oversized_frames_and_process_stat_handles_spaces_parentheses() {
        let mut frame = std::io::Cursor::new(((FRAME_LIMIT + 1) as u32).to_be_bytes());
        assert!(read_frame(&mut frame).is_err());
        let stat = format!(
            "123 (a name with ) parentheses) {}",
            (0..20).map(|i| i.to_string()).collect::<Vec<_>>().join(" ")
        );
        assert_eq!(process_start(&stat), Some(19));
        let inventory = Inventory {
            reasons: vec![ApplicationReason::ScanLimit; 100],
            ..Inventory::default()
        };
        assert!(inventory.validate().is_err());
    }

    #[test]
    fn actual_process_owns_its_listening_socket_and_closed_socket_disappears() {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        let config = ApplicationConfig {
            proc_root: "/proc".into(),
            ..ApplicationConfig::default()
        };
        let inventory = discover(&config);
        let endpoint = inventory
            .sockets
            .iter()
            .find(|s| s.port == port && s.protocol == 6)
            .unwrap();
        let owner = endpoint
            .owners
            .iter()
            .find(|o| o.pid == Some(std::process::id()))
            .unwrap();
        assert!(owner.process_start.is_some());
        assert!(owner.id.starts_with("process:"));
        drop(listener);
        assert!(
            !discover(&config)
                .sockets
                .iter()
                .any(|s| s.port == port && s.protocol == 6)
        );
    }
}
