use anyhow::{Context, Result, ensure};
use aya::{
    Ebpf, EbpfLoader,
    maps::{
        Array, HashMap, MapData, PerCpuArray, PerCpuHashMap, PerCpuValues, RingBuf,
        lpm_trie::{Key, LpmTrie},
    },
    programs::Xdp,
    util::nr_cpus,
};
use einblick_common::{
    Address, AssociationCounters, AssociationKey, Deadline, SourceCounters, SynEvent,
};
use einblick_core::{
    Config, MapHealth, Port, Rule, RuleKind, Source, Totals, TrafficCounts, TrafficRecord,
};
use ipnet::IpNet;
use std::{
    collections::BTreeMap,
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
};

pub fn monotonic_ns() -> u64 {
    let mut t = libc::timespec {
        tv_sec: 0,
        tv_nsec: 0,
    };
    unsafe { libc::clock_gettime(libc::CLOCK_MONOTONIC, &mut t) };
    t.tv_sec as u64 * 1_000_000_000 + t.tv_nsec as u64
}
fn address(ip: IpAddr) -> Address {
    match ip {
        IpAddr::V4(ip) => {
            let mut bytes = [0; 16];
            bytes[..4].copy_from_slice(&ip.octets());
            Address { bytes, family: 4 }
        }
        IpAddr::V6(ip) => Address {
            bytes: ip.octets(),
            family: 6,
        },
    }
}
fn ip(a: Address) -> IpAddr {
    if a.family == 4 {
        Ipv4Addr::new(a.bytes[0], a.bytes[1], a.bytes[2], a.bytes[3]).into()
    } else {
        Ipv6Addr::from(a.bytes).into()
    }
}
/// Deliberately bypass Aya's legacy netlink fallback: closing this FD must
/// detach on process death. BPF_LINK_CREATE does not replace an existing program.
fn attach_owned(
    program: std::os::fd::BorrowedFd<'_>,
    interface: &str,
    flags: u32,
) -> Result<std::os::fd::OwnedFd> {
    use aya_obj::generated::{bpf_attach_type, bpf_attr, bpf_cmd};
    use std::os::fd::{AsRawFd, FromRawFd};
    let name = std::ffi::CString::new(interface)?;
    let index = unsafe { libc::if_nametoindex(name.as_ptr()) };
    ensure!(index != 0, "unknown interface {interface}");
    let mut attr: bpf_attr = unsafe { std::mem::zeroed() };
    attr.link_create.__bindgen_anon_1.prog_fd = program.as_raw_fd() as u32;
    attr.link_create.__bindgen_anon_2.target_ifindex = index;
    attr.link_create.attach_type = bpf_attach_type::BPF_XDP as u32;
    attr.link_create.flags = flags;
    // The union is initialized, correctly aligned, and lives across this call.
    let result = unsafe {
        libc::syscall(
            libc::SYS_bpf,
            bpf_cmd::BPF_LINK_CREATE as u32,
            &attr,
            std::mem::size_of::<bpf_attr>(),
        )
    };
    if result < 0 {
        return Err(std::io::Error::last_os_error()).context("create owned XDP link");
    }
    // The kernel returned a new descriptor; OwnedFd closes it on every exit path.
    Ok(unsafe { std::os::fd::OwnedFd::from_raw_fd(result as i32) })
}

pub struct Observation {
    pub totals: Totals,
    pub sources: Vec<Source>,
    pub ports: Vec<Port>,
    pub syns: Vec<(IpAddr, u16)>,
    pub complete: bool,
    pub detail_complete: bool,
    pub traffic: Vec<TrafficRecord>,
    pub maps: Vec<MapHealth>,
    pub port_misses: u64,
    pub association_misses: u64,
}
#[derive(Default)]
struct DetailSample {
    ports: Vec<Port>,
    traffic: Vec<TrafficRecord>,
    complete: bool,
    port_used: usize,
    traffic_used: usize,
    port_misses: u64,
    association_misses: u64,
}
pub enum Backend {
    Kernel(Box<Kernel>),
    Mock(Mock),
}
impl Backend {
    pub fn new(config: &Config) -> Result<Self> {
        if config.mock {
            Ok(Self::Mock(Mock::default()))
        } else {
            Ok(Self::Kernel(Box::new(Kernel::load(config)?)))
        }
    }
    pub fn description(&self) -> (String, Vec<String>) {
        match self {
            Self::Kernel(k) => ("xdp".into(), k.attachments.clone()),
            Self::Mock(_) => ("mock · synthetic traffic".into(), vec![]),
        }
    }
    pub fn attach(&mut self, c: &Config) -> Result<()> {
        if let Self::Kernel(k) = self {
            k.attach(c)?;
        }
        Ok(())
    }
    pub fn poll(&mut self) -> Result<Observation> {
        match self {
            Self::Kernel(k) => k.poll(),
            Self::Mock(m) => Ok(m.poll()),
        }
    }
    pub fn reconcile(
        &mut self,
        rules: &[Rule],
        management: &[IpNet],
        blocking: bool,
        now: i64,
    ) -> Result<()> {
        match self {
            Self::Kernel(k) => k.reconcile(rules, management, blocking, now),
            Self::Mock(m) => {
                m.rules = rules.to_vec();
                m.management = management.to_vec();
                m.blocking = blocking;
                Ok(())
            }
        }
    }
    pub fn emergency(&mut self) -> Result<()> {
        match self {
            Self::Kernel(k) => {
                k.control.set(0, k.bank << 1, 0)?;
                Ok(())
            }
            Self::Mock(m) => {
                m.blocking = false;
                Ok(())
            }
        }
    }
}
struct Bank {
    allow4: LpmTrie<MapData, [u8; 4], Deadline>,
    allow6: LpmTrie<MapData, [u8; 16], Deadline>,
    block4: LpmTrie<MapData, [u8; 4], Deadline>,
    block6: LpmTrie<MapData, [u8; 16], Deadline>,
    bans: HashMap<MapData, Address, Deadline>,
}
impl Bank {
    fn take(bpf: &mut Ebpf, suffix: &str) -> Result<Self> {
        let mut map = |name: &str| {
            bpf.take_map(&format!("{name}_{suffix}"))
                .context("missing rule map")
        };
        Ok(Self {
            allow4: LpmTrie::try_from(map("ALLOW4")?)?,
            allow6: LpmTrie::try_from(map("ALLOW6")?)?,
            block4: LpmTrie::try_from(map("BLOCK4")?)?,
            block6: LpmTrie::try_from(map("BLOCK6")?)?,
            bans: HashMap::try_from(map("BANS")?)?,
        })
    }
    fn clear(&mut self) -> Result<()> {
        for trie in [&mut self.allow4, &mut self.block4] {
            let keys = trie.keys().collect::<std::result::Result<Vec<_>, _>>()?;
            for key in keys {
                trie.remove(&key)?;
            }
        }
        for trie in [&mut self.allow6, &mut self.block6] {
            let keys = trie.keys().collect::<std::result::Result<Vec<_>, _>>()?;
            for key in keys {
                trie.remove(&key)?;
            }
        }
        let keys = self
            .bans
            .keys()
            .collect::<std::result::Result<Vec<_>, _>>()?;
        for key in keys {
            self.bans.remove(&key)?;
        }
        Ok(())
    }
    fn fill(&mut self, rules: &[Rule], management: &[IpNet], now: i64) -> Result<()> {
        self.clear()?;
        let mono = monotonic_ns();
        for (allow, entries) in [
            (
                true,
                compiled_prefixes(rules, management, RuleKind::Allow, now),
            ),
            (false, compiled_prefixes(rules, &[], RuleKind::Block, now)),
        ] {
            for (network, expiry) in entries {
                let deadline = Deadline {
                    expires_ns: expiry.map_or(0, |e| {
                        mono.saturating_add((e - now).max(0) as u64 * 1_000_000_000)
                    }),
                };
                match network {
                    IpNet::V4(n) => {
                        if !allow && n.prefix_len() == 32 {
                            self.bans.insert(address(n.addr().into()), deadline, 0)?;
                        } else {
                            let key = Key::new(n.prefix_len() as u32, n.network().octets());
                            if allow {
                                self.allow4.insert(&key, deadline, 0)?;
                            } else {
                                self.block4.insert(&key, deadline, 0)?;
                            }
                        }
                    }
                    IpNet::V6(n) => {
                        if !allow && n.prefix_len() == 128 {
                            self.bans.insert(address(n.addr().into()), deadline, 0)?;
                        } else {
                            let key = Key::new(n.prefix_len() as u32, n.network().octets());
                            if allow {
                                self.allow6.insert(&key, deadline, 0)?;
                            } else {
                                self.block6.insert(&key, deadline, 0)?;
                            }
                        }
                    }
                }
            }
        }
        Ok(())
    }
}
/// Inherit ancestor deadlines so an expired narrow prefix cannot hide a live
/// broader rule between userspace reconciliation ticks. Permanent dominates.
fn compiled_prefixes(
    rules: &[Rule],
    management: &[IpNet],
    kind: RuleKind,
    now: i64,
) -> Vec<(IpNet, Option<i64>)> {
    let mut entries: BTreeMap<IpNet, Option<i64>> = BTreeMap::new();
    for r in rules.iter().filter(|r| r.kind == kind && r.active(now)) {
        entries
            .entry(r.network)
            .and_modify(|e| *e = longer(*e, r.expires))
            .or_insert(r.expires);
    }
    for &n in management {
        entries.insert(n.trunc(), None);
    }
    let all = entries.clone();
    entries
        .into_iter()
        .map(|(n, mut e)| {
            for (&parent, &expiry) in &all {
                if parent.prefix_len() <= n.prefix_len() && parent.contains(&n.addr()) {
                    e = longer(e, expiry);
                }
            }
            (n, e)
        })
        .collect()
}
fn longer(a: Option<i64>, b: Option<i64>) -> Option<i64> {
    match (a, b) {
        (Some(a), Some(b)) => Some(a.max(b)),
        _ => None,
    }
}
pub struct Kernel {
    ebpf: Ebpf,
    links: Vec<std::os::fd::OwnedFd>,
    pub attachments: Vec<String>,
    metrics: PerCpuArray<MapData, u64>,
    sources: PerCpuHashMap<MapData, Address, SourceCounters>,
    ports: [PerCpuHashMap<MapData, u32, u64>; 2],
    traffic: [PerCpuHashMap<MapData, AssociationKey, AssociationCounters>; 2],
    observation_bank: Array<MapData, u32>,
    writers: PerCpuArray<MapData, u64>,
    detail_loss: PerCpuArray<MapData, u64>,
    active_observation: u32,
    pending_observation: Option<usize>,
    interfaces: BTreeMap<u32, String>,
    events: RingBuf<MapData>,
    control: Array<MapData, u32>,
    banks: [Bank; 2],
    bank: u32,
    source_capacity: usize,
    port_capacity: usize,
    association_capacity: usize,
}
impl Kernel {
    fn load(c: &Config) -> Result<Self> {
        let bytes = aya::include_bytes_aligned!(concat!(env!("OUT_DIR"), "/einblick-ebpf"));
        ensure!(
            !bytes.is_empty(),
            "this binary has no embedded eBPF object; build with scripts/build.sh or use mock=true"
        );
        let cpus = nr_cpus().map_err(|(what, e)| anyhow::anyhow!("{what}: {e}"))?;
        let budget = (c.source_capacity as usize * (64 + cpus * 40)
            + 2 * c.port_capacity as usize * (32 + cpus * 8)
            + 2 * c.association_capacity as usize
                * (128 + cpus * std::mem::size_of::<AssociationCounters>())
            + cpus * 128
            + c.ring_bytes as usize
            + 4 * 1024 * 1024)
            * 2;
        ensure!(
            budget <= 64 * 1024 * 1024,
            "estimated kernel map allocation exceeds 64 MiB; reduce map capacities (host has {cpus} possible CPUs)"
        );
        let mut loader = EbpfLoader::new();
        loader
            .map_max_entries("SOURCES", c.source_capacity)
            .map_max_entries("PORTS_A", c.port_capacity)
            .map_max_entries("PORTS_B", c.port_capacity)
            .map_max_entries("TRAFFIC_A", c.association_capacity)
            .map_max_entries("TRAFFIC_B", c.association_capacity)
            .map_max_entries("EVENTS", c.ring_bytes);
        let mut bpf=loader.load(bytes).context("load eBPF maps: requires Linux 6.1+, CAP_BPF, permitted bpf syscall and sufficient memlock")?;
        let program: &mut Xdp = bpf
            .program_mut("ingress")
            .context("missing ingress program")?
            .try_into()?;
        program
            .load()
            .context("XDP load/verifier failed: live capture requires CAP_BPF, CAP_NET_ADMIN and CAP_PERFMON (for packet-pointer arithmetic), plus a permitted bpf syscall")?;
        let banks = [Bank::take(&mut bpf, "A")?, Bank::take(&mut bpf, "B")?];
        Ok(Self {
            metrics: PerCpuArray::try_from(bpf.take_map("METRICS").unwrap())?,
            sources: PerCpuHashMap::try_from(bpf.take_map("SOURCES").unwrap())?,
            ports: [
                PerCpuHashMap::try_from(bpf.take_map("PORTS_A").unwrap())?,
                PerCpuHashMap::try_from(bpf.take_map("PORTS_B").unwrap())?,
            ],
            traffic: [
                PerCpuHashMap::try_from(bpf.take_map("TRAFFIC_A").unwrap())?,
                PerCpuHashMap::try_from(bpf.take_map("TRAFFIC_B").unwrap())?,
            ],
            observation_bank: Array::try_from(bpf.take_map("OBSERVATION_BANK").unwrap())?,
            writers: PerCpuArray::try_from(bpf.take_map("WRITERS").unwrap())?,
            detail_loss: PerCpuArray::try_from(bpf.take_map("DETAIL_LOSS").unwrap())?,
            active_observation: 0,
            pending_observation: None,
            interfaces: BTreeMap::new(),
            events: RingBuf::try_from(bpf.take_map("EVENTS").unwrap())?,
            control: Array::try_from(bpf.take_map("CONTROL").unwrap())?,
            ebpf: bpf,
            links: vec![],
            attachments: vec![],
            banks,
            bank: 0,
            source_capacity: c.source_capacity as usize,
            port_capacity: c.port_capacity as usize,
            association_capacity: c.association_capacity as usize,
        })
    }
    fn attach(&mut self, c: &Config) -> Result<()> {
        let p: &mut Xdp = self.ebpf.program_mut("ingress").unwrap().try_into()?;
        for interface in &c.interfaces {
            let name = std::ffi::CString::new(interface.as_str())?;
            self.interfaces.insert(
                unsafe { libc::if_nametoindex(name.as_ptr()) },
                interface.clone(),
            );
            use std::os::fd::AsFd;
            let (fd, mode) = match attach_owned(
                p.fd()?.as_fd(),
                interface,
                aya_obj::generated::XDP_FLAGS_DRV_MODE,
            ) {
                Ok(fd) => (fd, "native"),
                Err(e) if c.generic_fallback => {
                    tracing::warn!(%e,%interface,"native XDP unavailable, trying generic owned link");
                    (attach_owned(p.fd()?.as_fd(),interface,2).context("generic owned XDP link failed; check BPF_LINK_CREATE support, permissions and existing XDP")?,"generic")
                }
                Err(e) => return Err(e),
            };
            self.links.push(fd);
            self.attachments.push(format!("{interface} · {mode}"));
        }
        Ok(())
    }
    fn reconcile(
        &mut self,
        rules: &[Rule],
        management: &[IpNet],
        blocking: bool,
        now: i64,
    ) -> Result<()> {
        let next = 1 - self.bank;
        self.banks[next as usize].fill(rules, management, now)?;
        self.control.set(0, (next << 1) | blocking as u32, 0)?;
        self.bank = next;
        Ok(())
    }
    fn poll(&mut self) -> Result<Observation> {
        let mut m = [0; einblick_common::METRICS_LEN as usize];
        for (i, v) in m.iter_mut().enumerate() {
            *v = self.metrics.get(&(i as u32), 0)?.iter().sum();
        }
        let totals = Totals {
            packets: m[0],
            bytes: m[1],
            passed: m[2],
            dropped: m[3],
            parse_limits: m[4],
            event_loss: m[5],
            map_full: m[6],
            source_misses: m[7],
            port_misses: m[8],
            association_misses: m[9],
        };
        let mut sources = vec![];
        let mut stale = vec![];
        let now = monotonic_ns();
        for entry in self.sources.iter().take(self.source_capacity) {
            let (a, values) = entry?;
            let last = values.iter().map(|v| v.last_seen).max().unwrap_or(0);
            if now.saturating_sub(last) > 120_000_000_000 {
                stale.push(a);
                continue;
            }
            sources.push(Source {
                ip: ip(a),
                ip_info: None,
                packets: values.iter().map(|v| v.packets).sum(),
                bytes: values.iter().map(|v| v.bytes).sum(),
                syns: values.iter().map(|v| v.syns).sum(),
                generation: values
                    .iter()
                    .filter(|v| v.first_seen > 0)
                    .map(|v| v.first_seen)
                    .min()
                    .unwrap_or(0),
            });
        }
        for a in stale {
            self.sources.remove(&a)?;
        }
        let detail = match self.collect_detail() {
            Ok(detail) => detail,
            Err(e) => {
                tracing::warn!(%e,"detail collection failed");
                DetailSample::default()
            }
        };
        let maps = vec![
            MapHealth {
                name: "sources".into(),
                used: sources.len(),
                capacity: self.source_capacity,
            },
            MapHealth {
                name: "ports / collected interval".into(),
                used: detail.port_used,
                capacity: self.port_capacity,
            },
            MapHealth {
                name: "IP detail / collected interval".into(),
                used: detail.traffic_used,
                capacity: self.association_capacity,
            },
        ];
        let mut syns = vec![];
        let mut complete = true;
        for _ in 0..65536 {
            let Some(item) = self.events.next() else {
                break;
            };
            if item.len() != std::mem::size_of::<SynEvent>() {
                complete = false;
                continue;
            }
            let e = unsafe { std::ptr::read_unaligned(item.as_ptr() as *const SynEvent) };
            if now.saturating_sub(e.time_ns) > 2_000_000_000 {
                complete = false;
                continue;
            }
            syns.push((ip(e.address), e.port));
        }
        if syns.len() == 65536 {
            complete = false;
        }
        Ok(Observation {
            totals,
            sources,
            ports: detail.ports,
            syns,
            complete,
            detail_complete: detail.complete,
            traffic: detail.traffic,
            maps,
            port_misses: detail.port_misses,
            association_misses: detail.association_misses,
        })
    }
    fn collect_detail(&mut self) -> Result<DetailSample> {
        let delayed = self.pending_observation.is_some();
        let bank = if let Some(bank) = self.pending_observation {
            bank
        } else {
            let old = self.active_observation as usize;
            self.active_observation = 1 - self.active_observation;
            self.observation_bank.set(0, self.active_observation, 0)?;
            self.pending_observation = Some(old);
            old
        };
        // After the selector update, observing zero once on each CPU proves all
        // old writers finished. New writers can only address the other bank.
        // A busy CPU must not block source/ring polling indefinitely.
        let deadline = std::time::Instant::now() + std::time::Duration::from_millis(10);
        let mut quiet = vec![false; self.writers.get(&0, 0)?.len()];
        loop {
            for (index, value) in self.writers.get(&0, 0)?.iter().enumerate() {
                quiet[index] |= *value == 0;
            }
            if quiet.iter().all(|v| *v) {
                break;
            }
            if std::time::Instant::now() >= deadline {
                return Ok(DetailSample::default());
            }
            std::thread::yield_now();
        }
        let port_entries = self.ports[bank]
            .iter()
            .collect::<std::result::Result<Vec<_>, _>>()?;
        let traffic_entries = self.traffic[bank]
            .iter()
            .collect::<std::result::Result<Vec<_>, _>>()?;
        let port_used = port_entries.len();
        let traffic_used = traffic_entries.len();
        let port_misses = self.detail_loss.get(&(bank as u32 * 2), 0)?.iter().sum();
        let association_misses = self
            .detail_loss
            .get(&(bank as u32 * 2 + 1), 0)?
            .iter()
            .sum();
        let ports = port_entries
            .iter()
            .map(|(key, values)| Port {
                protocol: (key >> 16) as u8,
                port: *key as u16,
                packets: values.iter().sum(),
            })
            .collect();
        let now = monotonic_ns();
        let wall = einblick_core::unix_now();
        let mut traffic = vec![];
        for (key, values) in &traffic_entries {
            let mut record = TrafficRecord {
                source: ip(key.source),
                destination: ip(key.destination),
                interface: self
                    .interfaces
                    .get(&key.interface)
                    .cloned()
                    .unwrap_or_else(|| key.interface.to_string()),
                protocol: key.protocol as u8,
                port: if key.parsed != 0 {
                    Some(key.port as u16)
                } else {
                    None
                },
                counts: TrafficCounts::default(),
                first_seen: wall,
                last_seen: 0,
                source_ports: vec![],
                source_ports_truncated: false,
                application_attribution: einblick_core::ApplicationAttribution::default(),
            };
            for v in values.iter().filter(|v| v.packets > 0) {
                let part = TrafficRecord {
                    counts: TrafficCounts {
                        packets: v.packets,
                        bytes: v.bytes,
                        passed: v.passed,
                        dropped: v.dropped,
                        syns: v.syns,
                        syn_acks: v.syn_acks,
                        resets: v.resets,
                    },
                    first_seen: wall - (now.saturating_sub(v.first_seen) / 1_000_000_000) as i64,
                    last_seen: wall - (now.saturating_sub(v.last_seen) / 1_000_000_000) as i64,
                    source_ports: v
                        .source_ports
                        .iter()
                        .take(v.source_port_count.min(8) as usize)
                        .copied()
                        .collect(),
                    source_ports_truncated: v.source_ports_truncated != 0,
                    ..record.clone()
                };
                record.merge(&part);
            }
            traffic.push(record);
        }
        // Only the quiescent bank is touched. If clearing fails, discard its
        // uncommitted snapshot and report a poll error instead of replaying it.
        for (key, _) in &port_entries {
            self.ports[bank].remove(key)?;
        }
        for (key, _) in &traffic_entries {
            self.traffic[bank].remove(key)?;
        }
        let cpus = self.writers.get(&0, 0)?.len();
        for index in [bank as u32 * 2, bank as u32 * 2 + 1] {
            self.detail_loss
                .set(index, PerCpuValues::try_from(vec![0; cpus])?, 0)?;
        }
        self.pending_observation = None;
        Ok(DetailSample {
            ports,
            traffic,
            complete: !delayed,
            port_used,
            traffic_used,
            port_misses,
            association_misses,
        })
    }
}
#[derive(Default)]
pub struct Mock {
    tick: u64,
    totals: Totals,
    rules: Vec<Rule>,
    management: Vec<IpNet>,
    blocking: bool,
    sources: BTreeMap<IpAddr, (u64, u64, u64)>,
    ports: BTreeMap<(u8, u16), u64>,
}
impl Mock {
    fn poll(&mut self) -> Observation {
        self.tick += 1;
        let now = einblick_core::unix_now();
        let mut syns = vec![];
        let mut traffic = vec![];
        self.ports.clear();
        for (ip, p, bytes, syn, port) in [
            ("192.0.2.24", 120 + self.tick % 30, 190_000, 2, 443),
            ("2001:db8::12", 50 + self.tick % 10, 64_000, 1, 22),
            ("198.51.100.9", 32, 2048, 32, (self.tick % 50 + 1) as u16),
        ] {
            let ip: IpAddr = ip.parse().unwrap();
            let allow = self.management.iter().any(|n| n.contains(&ip))
                || self
                    .rules
                    .iter()
                    .any(|r| r.kind == RuleKind::Allow && r.active(now) && r.network.contains(&ip));
            let block = self.blocking
                && !allow
                && self
                    .rules
                    .iter()
                    .any(|r| r.kind == RuleKind::Block && r.active(now) && r.network.contains(&ip));
            self.totals.packets += p;
            self.totals.bytes += bytes;
            if block {
                self.totals.dropped += p;
            } else {
                self.totals.passed += p;
            }
            let s = self.sources.entry(ip).or_default();
            s.0 += p;
            s.1 += bytes;
            s.2 += syn;
            *self.ports.entry((6, port)).or_default() += p;
            traffic.push(TrafficRecord {
                source: ip,
                destination: if ip.is_ipv4() {
                    "192.0.2.1".parse().unwrap()
                } else {
                    "2001:db8::1".parse().unwrap()
                },
                interface: "synthetic".into(),
                protocol: 6,
                port: Some(port),
                counts: TrafficCounts {
                    packets: p,
                    bytes,
                    passed: if block { 0 } else { p },
                    dropped: if block { p } else { 0 },
                    syns: syn,
                    syn_acks: 0,
                    resets: 0,
                },
                first_seen: now,
                last_seen: now,
                source_ports: vec![45000],
                source_ports_truncated: false,
                application_attribution: einblick_core::ApplicationAttribution::default(),
            });
            for _ in 0..syn {
                syns.push((ip, port));
            }
        }
        Observation {
            totals: self.totals.clone(),
            sources: self
                .sources
                .iter()
                .map(|(&ip, &(packets, bytes, syns))| Source {
                    ip,
                    packets,
                    bytes,
                    syns,
                    generation: 1,
                    ip_info: None,
                })
                .collect(),
            ports: self
                .ports
                .iter()
                .map(|(&(protocol, port), &packets)| Port {
                    protocol,
                    port,
                    packets,
                })
                .collect(),
            syns,
            complete: true,
            detail_complete: true,
            traffic,
            maps: vec![],
            port_misses: 0,
            association_misses: 0,
        }
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    fn rule(network: &str, expiry: Option<i64>) -> Rule {
        Rule {
            id: 1,
            network: network.parse().unwrap(),
            kind: RuleKind::Block,
            reason: "test".into(),
            actor: "admin".into(),
            created: 0,
            expires: expiry,
            enabled: true,
            applied: false,
            error: None,
        }
    }
    #[test]
    fn overlapping_expiry_inherits_ancestor() {
        let r = vec![
            rule("192.0.2.0/24", Some(100)),
            rule("192.0.2.128/25", Some(50)),
        ];
        let c = compiled_prefixes(&r, &[], RuleKind::Block, 1);
        assert!(c.iter().all(|(_, e)| *e == Some(100)));
        assert_eq!(compiled_prefixes(&r, &[], RuleKind::Block, 101).len(), 0);
    }
    #[test]
    fn mock_allow_precedes_block_and_expiry() {
        let mut m = Mock {
            blocking: true,
            rules: vec![rule("192.0.2.0/24", None)],
            ..Mock::default()
        };
        assert!(m.poll().totals.dropped > 0);
        m.management.push("192.0.2.24/32".parse().unwrap());
        assert_eq!(m.poll().totals.dropped, 120 + 1);
    }
}

#[cfg(test)]
mod kernel_tests {
    use super::*;
    use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
    fn frame(v6: bool, vlan: bool, fragment: bool) -> Vec<u8> {
        let mut b = vec![0; 14];
        b[..6].copy_from_slice(&[2, 0, 0, 0, 0, 1]);
        b[6..12].copy_from_slice(&[2, 0, 0, 0, 0, 2]);
        let ether = if v6 { 0x86ddu16 } else { 0x0800u16 };
        if vlan {
            b[12..14].copy_from_slice(&0x8100u16.to_be_bytes());
            b.extend_from_slice(&[0, 1]);
            b.extend_from_slice(&ether.to_be_bytes());
        } else {
            b[12..14].copy_from_slice(&ether.to_be_bytes());
        }
        let at = b.len();
        if v6 {
            b.resize(at + 60, 0);
            b[at] = 0x60;
            b[at + 4..at + 6].copy_from_slice(&20u16.to_be_bytes());
            b[at + 6] = 6;
            b[at + 7] = 64;
            b[at + 8..at + 24]
                .copy_from_slice(&"2001:db8::1".parse::<Ipv6Addr>().unwrap().octets());
            b[at + 24..at + 40]
                .copy_from_slice(&"2001:db8::2".parse::<Ipv6Addr>().unwrap().octets());
            b[at + 42..at + 44].copy_from_slice(&443u16.to_be_bytes());
            b[at + 52] = 0x50;
            b[at + 53] = 2;
        } else {
            b.resize(at + 40, 0);
            b[at] = 0x45;
            b[at + 2..at + 4].copy_from_slice(&40u16.to_be_bytes());
            b[at + 8] = 64;
            b[at + 9] = 6;
            b[at + 12..at + 16].copy_from_slice(&[192, 0, 2, 1]);
            b[at + 16..at + 20].copy_from_slice(&[192, 0, 2, 2]);
            b[at + 22..at + 24].copy_from_slice(&443u16.to_be_bytes());
            b[at + 32] = 0x50;
            b[at + 33] = 2;
            if fragment {
                b[at + 6] = 0x20;
            }
        }
        b
    }
    fn ipv6_extension_frame() -> Vec<u8> {
        let mut packet = frame(true, false, false);
        // Hop-by-hop, routing, destination options and AH, with different
        // lengths, followed by TCP. Exercise all four variable-offset steps.
        let mut extensions = vec![0; 60];
        for (at, next, length) in [(0, 43, 0), (8, 60, 1), (24, 51, 2), (48, 6, 1)] {
            extensions[at] = next;
            extensions[at + 1] = length;
        }
        packet.splice(54..54, extensions);
        packet[18..20].copy_from_slice(&80u16.to_be_bytes());
        packet[20] = 0;
        packet
    }
    #[test]
    fn ipv6_extension_fixture_and_truncations() {
        let frame = ipv6_extension_frame();
        let packet = einblick_common::parse(&frame);
        assert!(packet.has_address && packet.syn && !packet.limited);
        assert_eq!(packet.port, 443);
        assert_eq!(packet.protocol, 6);
        assert_eq!(packet.source.family, 6);
        for end in 0..frame.len() {
            let packet = einblick_common::parse(&frame[..end]);
            assert!(packet.limited && !packet.syn, "truncated at {end}");
        }
    }
    fn send_raw(frame: &[u8]) -> Result<()> {
        let raw = unsafe { libc::socket(libc::AF_PACKET, libc::SOCK_RAW, 3u16.to_be() as i32) };
        ensure!(raw >= 0, "raw socket: {}", std::io::Error::last_os_error());
        let socket = unsafe { OwnedFd::from_raw_fd(raw) };
        let index = unsafe { libc::if_nametoindex(c"eb-peer".as_ptr()) };
        ensure!(index != 0, "missing isolated eb-peer interface");
        let mut addr: libc::sockaddr_ll = unsafe { std::mem::zeroed() };
        addr.sll_family = libc::AF_PACKET as u16;
        addr.sll_ifindex = index as i32;
        addr.sll_halen = 6;
        addr.sll_addr[..6].copy_from_slice(&frame[..6]);
        let n = unsafe {
            libc::sendto(
                socket.as_raw_fd(),
                frame.as_ptr().cast(),
                frame.len(),
                0,
                (&addr as *const libc::sockaddr_ll).cast(),
                std::mem::size_of_val(&addr) as u32,
            )
        };
        ensure!(
            n == frame.len() as isize,
            "send frame: {}",
            std::io::Error::last_os_error()
        );
        Ok(())
    }
    fn send(frame: &[u8]) -> Result<()> {
        send_raw(frame)?;
        std::thread::sleep(std::time::Duration::from_millis(20));
        Ok(())
    }
    #[test]
    #[ignore = "requires root, an isolated network namespace and compiled embedded eBPF object; run scripts/test-kernel.sh"]
    fn xdp_namespace_rules_and_counters() -> Result<()> {
        let c = Config {
            interfaces: vec!["eb-test".into()],
            source_capacity: 128,
            port_capacity: 128,
            association_capacity: 128,
            ..Config::default()
        };
        let mut k = Backend::new(&c)?;
        k.reconcile(&[], &[], false, einblick_core::unix_now())?;
        if std::env::var_os("EINBLICK_TEST_GENERIC").is_some() {
            use std::os::fd::AsFd;
            let Backend::Kernel(inner) = &mut k else {
                unreachable!()
            };
            let p: &mut Xdp = inner.ebpf.program_mut("ingress").unwrap().try_into()?;
            inner
                .links
                .push(attach_owned(p.fd()?.as_fd(), "eb-test", 2)?);
            inner.interfaces.insert(
                unsafe { libc::if_nametoindex(c"eb-test".as_ptr()) },
                "eb-test".into(),
            );
            inner.attachments.push("eb-test · generic".into());
        } else {
            k.attach(&c)?;
        }
        println!("XDP attachment: {:?}", k.description().1);
        let old = k.poll()?.totals;
        let packet = frame(false, false, false);
        send(&packet)?;
        let obs = k.poll()?;
        ensure!(obs.totals.passed > old.passed, "IPv4 pass");
        ensure!(
            obs.totals.bytes >= old.bytes + packet.len() as u64,
            "global byte counter includes the complete Ethernet frame"
        );
        let source = obs
            .sources
            .iter()
            .find(|source| source.ip == "192.0.2.1".parse::<IpAddr>().unwrap())
            .context("missing IPv4 source counters")?;
        ensure!(
            source.packets == 1 && source.bytes == packet.len() as u64,
            "source byte counter uses the kernel's scalar packet length"
        );
        ensure!(
            obs.syns
                .iter()
                .any(|(ip, p)| *ip == "192.0.2.1".parse::<IpAddr>().unwrap() && *p == 443),
            "TCP SYN event"
        );
        ensure!(
            obs.traffic
                .iter()
                .any(|r| r.source == "192.0.2.1".parse::<IpAddr>().unwrap()
                    && r.port == Some(443)
                    && r.counts.syns == 1),
            "source-to-port association"
        );
        // More distinct ports across intervals than either map can hold must
        // remain observable, rather than exhausting a cumulative hash table.
        let misses = obs.totals.port_misses;
        for batch in 0..4 {
            for offset in 0..64 {
                let mut frame = packet.clone();
                frame[36..38].copy_from_slice(&(1000 + batch * 64 + offset as u16).to_be_bytes());
                send(&frame)?;
            }
            let obs = k.poll()?;
            ensure!(
                obs.detail_complete && obs.totals.port_misses == misses,
                "port churn exhausted an interval map"
            );
            ensure!(
                obs.ports
                    .iter()
                    .filter(|p| p.port >= 1000 && p.port < 1256)
                    .count()
                    == 64,
                "interval port rows missing"
            );
        }
        let mut concurrent = packet.clone();
        concurrent[36..38].copy_from_slice(&53100u16.to_be_bytes());
        concurrent[47] = 0x12;
        let sender = std::thread::spawn(move || -> Result<()> {
            for _ in 0..1000 {
                send_raw(&concurrent)?;
            }
            Ok(())
        });
        let mut recorded = 0;
        let mut associated = 0;
        while !sender.is_finished() {
            let obs = k.poll()?;
            recorded += obs
                .ports
                .iter()
                .filter(|p| p.port == 53100)
                .map(|p| p.packets)
                .sum::<u64>();
            associated += obs
                .traffic
                .iter()
                .filter(|r| r.port == Some(53100))
                .map(|r| r.counts.syn_acks)
                .sum::<u64>();
        }
        sender.join().unwrap()?;
        for _ in 0..2 {
            let obs = k.poll()?;
            recorded += obs
                .ports
                .iter()
                .filter(|p| p.port == 53100)
                .map(|p| p.packets)
                .sum::<u64>();
            associated += obs
                .traffic
                .iter()
                .filter(|r| r.port == Some(53100))
                .map(|r| r.counts.syn_acks)
                .sum::<u64>();
        }
        ensure!(
            recorded == 1000,
            "concurrent bank switches lost or duplicated packets: {recorded}"
        );
        ensure!(
            associated == 1000,
            "concurrent association count: {associated}"
        );
        // Real within-interval overflow stays explicit and clears next interval.
        for port in 54000u16..54200 {
            let mut frame = packet.clone();
            frame[36..38].copy_from_slice(&port.to_be_bytes());
            frame[47] = 0x12;
            send_raw(&frame)?;
        }
        let overflow = k.poll()?;
        ensure!(
            overflow.port_misses > 0 && overflow.association_misses > 0,
            "capacity overflow was not recorded"
        );
        send(&packet)?;
        let recovered = k.poll()?;
        ensure!(
            recovered.detail_complete
                && recovered.port_misses == 0
                && recovered.association_misses == 0,
            "capacity did not recover on rotation"
        );
        let mut udp = packet.clone();
        udp[23] = 17;
        udp[34..36].copy_from_slice(&52000u16.to_be_bytes());
        udp[36..38].copy_from_slice(&0u16.to_be_bytes());
        udp[38..40].copy_from_slice(&8u16.to_be_bytes());
        send(&udp)?;
        let mut icmp = packet.clone();
        icmp[23] = 1;
        send(&icmp)?;
        send(&frame(false, false, true))?;
        for port in 50000u16..50012 {
            let mut sample = packet.clone();
            sample[34..36].copy_from_slice(&port.to_be_bytes());
            sample[36..38].copy_from_slice(&55000u16.to_be_bytes());
            sample[47] = 0x12;
            send_raw(&sample)?;
        }
        let mut reset = packet.clone();
        reset[47] = 4;
        send(&reset)?;
        let detail = k.poll()?.traffic;
        ensure!(
            detail
                .iter()
                .any(|r| r.protocol == 17 && r.port == Some(0) && r.source_ports == [52000]),
            "UDP port zero association"
        );
        ensure!(
            detail.iter().any(|r| r.protocol == 1 && r.port.is_none()),
            "ICMP protocol-only association"
        );
        ensure!(
            detail.iter().any(|r| r.protocol == 6 && r.port.is_none()),
            "fragment retains unknown transport"
        );
        ensure!(
            detail.iter().any(|r| r.port == Some(55000)
                && r.counts.syn_acks == 12
                && r.source_ports.len() == 8
                && r.source_ports_truncated),
            "bounded source-port sample"
        );
        ensure!(
            detail.iter().any(|r| r.port == Some(443)
                && r.counts.resets == 1
                && r.destination == "192.0.2.2".parse::<IpAddr>().unwrap()),
            "RST/destination association"
        );
        send(&ipv6_extension_frame())?;
        let obs = k.poll()?;
        ensure!(
            obs.syns
                .iter()
                .any(|(ip, port)| *ip == "2001:db8::1".parse::<IpAddr>().unwrap() && *port == 443),
            "TCP SYN after four IPv6 extension headers"
        );
        let now = einblick_core::unix_now();
        let mut rules = vec![
            Rule {
                id: 1,
                network: "192.0.2.0/24".parse()?,
                kind: RuleKind::Block,
                reason: "test".into(),
                actor: "test".into(),
                created: now,
                expires: None,
                enabled: true,
                applied: false,
                error: None,
            },
            Rule {
                id: 2,
                network: "2001:db8::/32".parse()?,
                kind: RuleKind::Block,
                reason: "test".into(),
                actor: "test".into(),
                created: now,
                expires: None,
                enabled: true,
                applied: false,
                error: None,
            },
        ];
        k.reconcile(&rules, &[], true, now)?;
        let old = k.poll()?.totals;
        send(&frame(false, false, false))?;
        send(&frame(true, false, false))?;
        send(&frame(false, true, false))?;
        send(&frame(false, false, true))?;
        send(&ipv6_extension_frame())?;
        let blocked = k.poll()?;
        ensure!(
            blocked
                .traffic
                .iter()
                .map(|r| r.counts.dropped)
                .sum::<u64>()
                >= 5,
            "association drop disposition"
        );
        let after = blocked.totals;
        ensure!(
            after.dropped >= old.dropped + 5,
            "IPv4, IPv6, VLAN, fragment and IPv6 extension source blocks"
        );
        k.reconcile(&rules, &["192.0.2.1/32".parse()?], true, now)?;
        let old = k.poll()?.totals;
        send(&frame(false, false, false))?;
        ensure!(k.poll()?.totals.passed > old.passed, "allowlist precedence");
        rules[0].network = "192.0.2.1/32".parse()?;
        rules[0].expires = Some(now + 2);
        k.reconcile(&rules, &[], true, now)?;
        std::thread::sleep(std::time::Duration::from_secs(3));
        let old = k.poll()?.totals;
        send(&frame(false, false, false))?;
        ensure!(
            k.poll()?.totals.passed > old.passed,
            "kernel ban expiry without reconciliation"
        );
        k.emergency()?;
        let old = k.poll()?.totals;
        send(&frame(true, false, false))?;
        ensure!(k.poll()?.totals.passed > old.passed, "emergency disable");
        let mut conflict = Backend::new(&c)?;
        ensure!(
            conflict.attach(&c).is_err(),
            "existing XDP must not be replaced"
        );
        Ok(())
    }
}
