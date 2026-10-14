//! Service observations and the shared live/playground evaluator. No enforcement here.
use anyhow::{Result, ensure};
use regex::{Regex, RegexBuilder};
use serde::{Deserialize, Serialize};
use std::{
    collections::{BTreeMap, HashMap, VecDeque},
    net::IpAddr,
};

pub const MAX_LINE: usize = 8192;
pub const MAX_SAMPLE: usize = 128 * 1024;
pub const MAX_EVENTS: usize = 65536;

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProtectedService {
    #[serde(default)]
    pub id: i64,
    #[serde(default)]
    pub revision: i64,
    pub name: String,
    #[serde(default)]
    pub description: String,
    #[serde(default = "yes")]
    pub enabled: bool,
    #[serde(default = "yes")]
    pub observe_only: bool,
    #[serde(default)]
    pub sources: Vec<LogSource>,
    #[serde(default)]
    pub policies: Vec<Policy>,
    #[serde(default)]
    pub scope: BanScope,
}
fn yes() -> bool {
    true
}
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BanScope {
    #[default]
    SourceIp,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LogSource {
    pub id: String,
    pub name: String,
    #[serde(default = "yes")]
    pub enabled: bool,
    pub input: SourceInput,
    pub filters: Vec<Filter>,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum SourceInput {
    File { path: String },
    Journal { unit: String },
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Filter {
    pub id: String,
    pub name: String,
    #[serde(default = "yes")]
    pub enabled: bool,
    pub patterns: Vec<String>,
    pub event_type: String,
    #[serde(default = "ip_capture")]
    pub ip_capture: String,
    #[serde(default)]
    pub subject_capture: Option<String>,
    /// Unix seconds or RFC3339. Missing capture means observation time, explicitly attributed.
    #[serde(default)]
    pub timestamp_capture: Option<String>,
}
fn ip_capture() -> String {
    "source_ip".into()
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Policy {
    pub id: String,
    pub name: String,
    #[serde(default = "yes")]
    pub enabled: bool,
    #[serde(default = "yes")]
    pub observe_only: bool,
    pub event_types: Vec<String>,
    pub threshold: usize,
    pub window_seconds: i64,
    pub ban_seconds: i64,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SecurityEvent {
    pub at: i64,
    pub observed_at: i64,
    pub timestamp_origin: String,
    pub service_id: i64,
    pub source_id: String,
    pub filter_id: String,
    pub event_type: String,
    pub source_ip: IpAddr,
    pub subject: Option<String>,
    pub evidence: String,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct MatchResult {
    pub line: usize,
    pub filter_id: String,
    pub status: String,
    pub pattern: Option<usize>,
    pub event: Option<SecurityEvent>,
    pub error: Option<String>,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PolicyHit {
    pub at: i64,
    pub service_id: i64,
    pub revision: i64,
    pub service_name: String,
    pub policy_id: String,
    pub policy_name: String,
    pub source_ip: IpAddr,
    pub count: usize,
    pub window_seconds: i64,
    pub ban_seconds: i64,
    pub observe_only: bool,
    pub evidence: SecurityEvent,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Simulation {
    pub matches: Vec<MatchResult>,
    pub counts: BTreeMap<String, usize>,
    pub decisions: Vec<PolicyHit>,
    pub potentially_preventable: usize,
    pub source_counts: BTreeMap<String, usize>,
    pub filter_counts: BTreeMap<String, usize>,
    pub policy_counts: BTreeMap<String, usize>,
    pub timing: String,
}
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct SourceState {
    #[serde(default)]
    pub revision: i64,
    pub cursor: String,
    pub status: String,
    pub error: Option<String>,
    pub updated: i64,
    pub entries: u64,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct StoredEvent {
    pub id: i64,
    pub event: SecurityEvent,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Decision {
    pub id: i64,
    pub hit: PolicyHit,
    pub status: String,
    pub rule_id: Option<i64>,
    pub rule: Option<crate::Rule>,
}

fn text(s: &str, max: usize) -> bool {
    !s.trim().is_empty() && s.len() <= max && !s.chars().any(char::is_control)
}
fn identifier(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= 64
        && s.chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-')
}
impl SourceInput {
    pub fn validate(&self) -> Result<()> {
        match self {
            SourceInput::File { path } => ensure!(
                std::path::Path::new(path).is_absolute()
                    && path.len() <= 4096
                    && !path.contains('\0'),
                "absolute log path required"
            ),
            SourceInput::Journal { unit } => ensure!(
                unit.ends_with(".service")
                    && unit.len() > 8
                    && unit.len() <= 256
                    && unit
                        .chars()
                        .all(|c| c.is_ascii_alphanumeric() || "@._:-\\".contains(c)),
                "invalid systemd service unit"
            ),
        }
        Ok(())
    }
}
impl ProtectedService {
    pub fn validate(&self) -> Result<()> {
        ensure!(
            text(&self.name, 128) && self.description.len() <= 2048,
            "invalid service name or description"
        );
        ensure!(
            self.sources.len() <= 8 && self.policies.len() <= 16,
            "at most 8 sources and 16 policies per service"
        );
        let mut ids = std::collections::HashSet::new();
        let pattern_count: usize = self
            .sources
            .iter()
            .flat_map(|s| &s.filters)
            .map(|f| f.patterns.len())
            .sum();
        let pattern_bytes: usize = self
            .sources
            .iter()
            .flat_map(|s| &s.filters)
            .flat_map(|f| &f.patterns)
            .map(String::len)
            .sum();
        ensure!(
            pattern_count <= 32 && pattern_bytes <= 16384,
            "service regex budget: at most 32 patterns and 16 KiB pattern text"
        );
        for s in &self.sources {
            ensure!(
                identifier(&s.id) && ids.insert(&s.id) && text(&s.name, 128),
                "invalid or duplicate source identity"
            );
            s.input.validate()?;
            ensure!(
                !s.filters.is_empty() && s.filters.len() <= 8,
                "each source needs 1–8 filters"
            );
            let mut filters = std::collections::HashSet::new();
            for f in &s.filters {
                ensure!(filters.insert(&f.id), "duplicate filter identity");
                CompiledFilter::new(f)?;
            }
        }
        ids.clear();
        for p in &self.policies {
            ensure!(
                identifier(&p.id) && ids.insert(&p.id) && text(&p.name, 128),
                "invalid or duplicate policy identity"
            );
            ensure!(
                !p.event_types.is_empty()
                    && p.event_types.len() <= 16
                    && p.event_types.iter().all(|s| identifier(s)),
                "invalid event types"
            );
            ensure!(
                (1..=1000).contains(&p.threshold)
                    && (1..=86400).contains(&p.window_seconds)
                    && (1..=604800).contains(&p.ban_seconds),
                "policy limits: threshold 1–1000, window 1–86400s, ban 1–604800s"
            );
        }
        Ok(())
    }
}
pub struct CompiledFilter {
    pub filter: Filter,
    patterns: Vec<Regex>,
}
impl CompiledFilter {
    pub fn new(f: &Filter) -> Result<Self> {
        ensure!(
            identifier(&f.id) && text(&f.name, 128) && identifier(&f.event_type),
            "invalid filter identity, name or event type"
        );
        ensure!(
            !f.patterns.is_empty() && f.patterns.len() <= 8,
            "filter needs 1–8 patterns"
        );
        let mut patterns = Vec::new();
        for pattern in &f.patterns {
            ensure!(
                !pattern.is_empty() && pattern.len() <= 2048,
                "pattern must contain 1–2048 bytes"
            );
            let re = RegexBuilder::new(pattern)
                .size_limit(128 * 1024)
                .dfa_size_limit(64 * 1024)
                .nest_limit(32)
                .build()?;
            for capture in std::iter::once(&f.ip_capture)
                .chain(f.subject_capture.iter())
                .chain(f.timestamp_capture.iter())
            {
                ensure!(
                    identifier(capture) && re.capture_names().flatten().any(|n| n == capture),
                    "missing named capture: {capture}"
                );
            }
            patterns.push(re);
        }
        Ok(Self {
            filter: f.clone(),
            patterns,
        })
    }
    pub fn parse(
        &self,
        service_id: i64,
        source_id: &str,
        line: &str,
        number: usize,
        at: i64,
    ) -> MatchResult {
        let f = &self.filter;
        let mut result = MatchResult {
            line: number,
            filter_id: f.id.clone(),
            status: "ignored".into(),
            pattern: None,
            event: None,
            error: None,
        };
        if !f.enabled {
            return result;
        }
        let parse = || -> Result<Option<(usize, SecurityEvent)>> {
            ensure!(line.len() <= MAX_LINE, "line exceeds 8192 bytes");
            for (i, re) in self.patterns.iter().enumerate() {
                if let Some(c) = re.captures(line) {
                    let ip: IpAddr = c
                        .name(&f.ip_capture)
                        .ok_or_else(|| anyhow::anyhow!("source IP capture absent"))?
                        .as_str()
                        .parse()?;
                    let timestamp = f
                        .timestamp_capture
                        .as_ref()
                        .map(|name| -> Result<i64> {
                            let value = c
                                .name(name)
                                .ok_or_else(|| anyhow::anyhow!("timestamp capture absent"))?
                                .as_str();
                            if let Ok(n) = value.parse::<i64>() {
                                ensure!(
                                    (0..=253402300799).contains(&n),
                                    "timestamp outside supported Unix range"
                                );
                                Ok(n)
                            } else {
                                let n = chrono::DateTime::parse_from_rfc3339(value)?.timestamp();
                                ensure!(
                                    (0..=253402300799).contains(&n),
                                    "timestamp outside supported Unix range"
                                );
                                Ok(n)
                            }
                        })
                        .transpose()?;
                    return Ok(Some((
                        i,
                        SecurityEvent {
                            at: timestamp.unwrap_or(at),
                            observed_at: at,
                            timestamp_origin: if timestamp.is_some() {
                                "log"
                            } else {
                                "observation"
                            }
                            .into(),
                            service_id,
                            source_id: source_id.into(),
                            filter_id: f.id.clone(),
                            event_type: f.event_type.clone(),
                            source_ip: ip,
                            subject: f
                                .subject_capture
                                .as_ref()
                                .and_then(|n| c.name(n))
                                .map(|m| m.as_str().chars().take(256).collect()),
                            evidence: line.into(),
                        },
                    )));
                }
            }
            Ok(None)
        };
        match parse() {
            Ok(Some((i, e))) => {
                result.pattern = Some(i);
                result.status = "matched".into();
                result.event = Some(e);
            }
            Ok(None) => {}
            Err(e) => {
                result.status = "extraction_failed".into();
                result.error = Some(e.to_string());
                result.pattern = self.patterns.iter().position(|r| r.is_match(line));
            }
        }
        result
    }
}

#[derive(Default)]
pub struct PolicyEngine {
    windows: HashMap<(String, IpAddr), VecDeque<i64>>,
    cooldown: HashMap<(String, IpAddr), i64>,
    last: Option<i64>,
    samples: usize,
}
impl PolicyEngine {
    pub fn clear(&mut self) {
        *self = Self::default();
    }
    pub fn evaluate(
        &mut self,
        service: &ProtectedService,
        event: &SecurityEvent,
    ) -> Result<Vec<PolicyHit>> {
        ensure!(
            (0..=253402300799).contains(&event.at),
            "invalid event timestamp"
        );
        if !service.enabled {
            return Ok(vec![]);
        }
        ensure!(
            self.last.is_none_or(|t| event.at >= t),
            "out-of-order evidence; rebuild window"
        );
        self.last = Some(event.at);
        let max_window = service
            .policies
            .iter()
            .map(|p| p.window_seconds)
            .max()
            .unwrap_or(1);
        self.windows.retain(|_, q| {
            while q.front().is_some_and(|t| *t <= event.at - max_window) {
                q.pop_front();
            }
            !q.is_empty()
        });
        self.cooldown.retain(|_, until| *until > event.at);
        self.samples = self.windows.values().map(VecDeque::len).sum();
        let mut hits = vec![];
        for p in service
            .policies
            .iter()
            .filter(|p| p.enabled && p.event_types.contains(&event.event_type))
        {
            let key = (p.id.clone(), event.source_ip);
            ensure!(
                self.windows.len() < 1024 || self.windows.contains_key(&key),
                "policy IP capacity reached"
            );
            ensure!(self.samples < 8192, "policy evidence capacity reached");
            let q = self.windows.entry(key.clone()).or_default();
            while q.front().is_some_and(|t| *t <= event.at - p.window_seconds) {
                q.pop_front();
                self.samples = self.samples.saturating_sub(1);
            }
            q.push_back(event.at);
            self.samples += 1;
            while q.len() > p.threshold {
                q.pop_front();
                self.samples -= 1;
            }
            if q.len() >= p.threshold && !self.cooldown.contains_key(&key) {
                ensure!(
                    self.cooldown.len() < 1024,
                    "policy cooldown capacity reached"
                );
                self.cooldown.insert(key, event.at + p.ban_seconds);
                hits.push(PolicyHit {
                    at: event.at,
                    service_id: service.id,
                    revision: service.revision,
                    service_name: service.name.clone(),
                    policy_id: p.id.clone(),
                    policy_name: p.name.clone(),
                    source_ip: event.source_ip,
                    count: q.len(),
                    window_seconds: p.window_seconds,
                    ban_seconds: p.ban_seconds,
                    observe_only: service.observe_only || p.observe_only,
                    evidence: event.clone(),
                });
            }
        }
        Ok(hits)
    }
}
pub fn simulate_events(
    service: &ProtectedService,
    mut events: Vec<SecurityEvent>,
) -> Result<Simulation> {
    service.validate()?;
    ensure!(
        events.len() <= MAX_EVENTS,
        "simulation event limit exceeded"
    );
    events.sort_by_key(|e| e.at);
    let mut engine = PolicyEngine::default();
    let mut result=Simulation{matches:vec![],counts:BTreeMap::new(),decisions:vec![],potentially_preventable:0,source_counts:BTreeMap::new(),filter_counts:BTreeMap::new(),policy_counts:BTreeMap::new(),timing:"Recorded event timestamps; estimates later matching events inside a hypothetical whole-IP ban. Not proof of prevention.".into()};
    let mut bans: HashMap<IpAddr, i64> = HashMap::new();
    for e in events {
        *result.source_counts.entry(e.source_id.clone()).or_default() += 1;
        *result
            .filter_counts
            .entry(format!("{}:{}", e.source_id, e.filter_id))
            .or_default() += 1;
        *result.counts.entry(e.source_ip.to_string()).or_default() += 1;
        if bans.get(&e.source_ip).is_some_and(|until| *until > e.at) {
            result.potentially_preventable += 1;
        }
        for hit in engine.evaluate(service, &e)? {
            *result
                .policy_counts
                .entry(hit.policy_id.clone())
                .or_default() += 1;
            bans.entry(hit.source_ip)
                .and_modify(|until| *until = (*until).max(hit.at + hit.ban_seconds))
                .or_insert(hit.at + hit.ban_seconds);
            result.decisions.push(hit);
        }
    }
    Ok(result)
}
pub fn playground(
    service: &ProtectedService,
    source_id: &str,
    input: &str,
    at: i64,
    spacing: i64,
) -> Result<Simulation> {
    service.validate()?;
    ensure!(
        input.len() <= MAX_SAMPLE && input.lines().count() <= 1000 && (0..=3600).contains(&spacing),
        "sample limit: 128 KiB, 1000 lines, spacing 0–3600 seconds"
    );
    let source = service
        .sources
        .iter()
        .find(|s| s.id == source_id)
        .ok_or_else(|| anyhow::anyhow!("source not found"))?;
    let filters = source
        .filters
        .iter()
        .map(CompiledFilter::new)
        .collect::<Result<Vec<_>>>()?;
    let mut matches = vec![];
    let mut events = vec![];
    for (i, line) in input.lines().enumerate() {
        let mut seen = std::collections::HashSet::new();
        for filter in &filters {
            let r = filter.parse(service.id, source_id, line, i + 1, at + i as i64 * spacing);
            if let Some(e) = &r.event
                && seen.insert((e.source_ip, e.event_type.clone()))
            {
                events.push(e.clone());
            }
            matches.push(r);
        }
    }
    let mut simulated_service = service.clone();
    simulated_service.enabled &= source.enabled;
    let mut result = simulate_events(&simulated_service, events)?;
    result.matches = matches;
    result.timing = format!(
        "Timestamp capture where configured; otherwise synthetic spacing of {spacing}s. Disabled sources/policies are excluded. Observe flags and global allowlists do not change hypothetical thresholds; live enforcement still checks them."
    );
    if result.matches.iter().any(|m| m.error.is_some()) {
        result.decisions.clear();
        result.policy_counts.clear();
        result.potentially_preventable = 0;
        result.timing.push_str(" Extraction errors found: live evidence would be reset; no ban is eligible for this batch.");
    }
    Ok(result)
}
pub fn ssh_template() -> ProtectedService {
    ProtectedService{id:0,revision:0,name:"OpenSSH".into(),description:"SSH authentication failures. Verify the unit and samples before enabling enforcement. Whole source IP scope.".into(),enabled:true,observe_only:true,scope:BanScope::SourceIp,sources:vec![LogSource{id:"ssh-journal".into(),name:"SSH journal".into(),enabled:true,input:SourceInput::Journal{unit:"ssh.service".into()},filters:vec![Filter{id:"ssh-failures".into(),name:"OpenSSH authentication failures".into(),enabled:true,patterns:vec![r"Failed (?:password|publickey|keyboard-interactive(?:/pam)?) for (?:invalid user )?(?P<subject>\S+) from (?P<source_ip>[0-9a-fA-F:.]+) port \d+".into(),r"Invalid user (?P<subject>\S+) from (?P<source_ip>[0-9a-fA-F:.]+) port \d+".into(),r"authentication failure;.*rhost=(?P<source_ip>[0-9a-fA-F:.]+)(?:\s+user=(?P<subject>\S+))?".into()],event_type:"authentication_failure".into(),ip_capture:ip_capture(),subject_capture:Some("subject".into()),timestamp_capture:None}]}],policies:vec![Policy{id:"ssh-brute-force".into(),name:"Repeated authentication failures".into(),enabled:true,observe_only:true,event_types:vec!["authentication_failure".into()],threshold:5,window_seconds:300,ban_seconds:600}]}
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn ssh_variants_and_extraction() {
        let s = ssh_template();
        s.validate().unwrap();
        let sample = "Failed password for invalid user bot from 192.0.2.1 port 44 ssh2\nFailed publickey for root from 2001:db8::1 port 44 ssh2\nInvalid user bot from 192.0.2.1 port 44\npam_unix(sshd:auth): authentication failure; rhost=192.0.2.1 user=root\nFailed password for root from 999.2.3.4 port 44\naccepted";
        let result = playground(&s, "ssh-journal", sample, 100, 1).unwrap();
        assert_eq!(
            result
                .matches
                .iter()
                .filter(|m| m.status == "matched")
                .count(),
            4
        );
        assert_eq!(result.matches[4].status, "extraction_failed");
        assert_eq!(result.matches[5].status, "ignored");
    }
    #[test]
    fn rolling_window_and_historical_estimate() {
        let mut s = ssh_template();
        s.policies[0].threshold = 2;
        s.policies[0].window_seconds = 10;
        let line = "Failed password for root from 192.0.2.1 port 44";
        let r = playground(&s, "ssh-journal", &[line; 4].join("\n"), 100, 1).unwrap();
        assert_eq!(r.decisions.len(), 1);
        assert_eq!(r.potentially_preventable, 2);
        assert!(r.decisions[0].observe_only);
        let r = playground(&s, "ssh-journal", &[line; 4].join("\n"), 100, 10).unwrap();
        assert!(r.decisions.is_empty());
    }
    #[test]
    fn malformed_and_expensive_regex_rejected() {
        let mut s = ssh_template();
        s.sources[0].filters[0].patterns = vec!["(".into()];
        assert!(s.validate().is_err());
        s.sources[0].filters[0].patterns = vec![r"(?P<source_ip>a{100000000})".into()];
        assert!(s.validate().is_err());
    }
    #[test]
    fn independent_policies_and_clear_on_gap() {
        let mut s = ssh_template();
        s.policies[0].threshold = 2;
        let mut p = s.policies[0].clone();
        p.id = "second".into();
        s.policies.push(p);
        let e = playground(
            &s,
            "ssh-journal",
            "Failed password for root from 192.0.2.1 port 44",
            100,
            1,
        )
        .unwrap()
        .matches[0]
            .event
            .clone()
            .unwrap();
        let mut engine = PolicyEngine::default();
        assert!(engine.evaluate(&s, &e).unwrap().is_empty());
        let mut next = e.clone();
        next.at = 101;
        assert_eq!(engine.evaluate(&s, &next).unwrap().len(), 2);
        assert!(engine.evaluate(&s, &e).is_err());
        engine.clear();
        assert!(engine.evaluate(&s, &next).unwrap().is_empty());
    }
    #[test]
    fn duplicate_filters_disabled_sources_and_timestamp_capture() {
        let mut service = ssh_template();
        service.policies[0].threshold = 1;
        let mut filter = service.sources[0].filters[0].clone();
        filter.id = "duplicate".into();
        service.sources[0].filters.push(filter);
        let sample = "Failed password for root from 192.0.2.1 port 44";
        let result = playground(&service, "ssh-journal", sample, 100, 1).unwrap();
        assert_eq!(result.counts["192.0.2.1"], 1);
        assert_eq!(result.matches.len(), 2);
        service.sources[0].enabled = false;
        assert!(
            playground(&service, "ssh-journal", sample, 100, 1)
                .unwrap()
                .decisions
                .is_empty()
        );
        let mut filter = service.sources[0].filters[0].clone();
        filter.subject_capture = None;
        filter.timestamp_capture = Some("at".into());
        filter.patterns = vec![r"(?P<at>\S+) (?P<source_ip>\S+)".into()];
        let parser = CompiledFilter::new(&filter).unwrap();
        let event = parser
            .parse(1, "source", "2026-01-01T00:00:00Z 2001:db8::1", 1, 200)
            .event
            .unwrap();
        assert_eq!(event.timestamp_origin, "log");
        assert_eq!(event.at, 1767225600);
        assert_eq!(
            parser
                .parse(1, "source", "corrupt 192.0.2.1", 1, 200)
                .status,
            "extraction_failed"
        );
    }
}
