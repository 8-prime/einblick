use serde::{Deserialize, Serialize};

pub const APPLICATION_LIMIT: usize = 8;
pub const APPLICATION_TEXT_LIMIT: usize = 128;
pub const APPLICATION_BYTE_LIMIT: usize = 4096;

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ApplicationMethod {
    SocketOwner,
    PublishedPort,
    Configured,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ApplicationEvidence {
    pub id: String,
    pub name: String,
    pub method: ApplicationMethod,
    pub pid: Option<u32>,
    pub process_start: Option<u64>,
    pub executable: Option<String>,
    pub service: Option<String>,
    pub container_id: Option<String>,
    pub observed_from: i64,
    pub observed_to: i64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ApplicationReason {
    NotCollected,
    Disabled,
    Waiting,
    CollectorUnavailable,
    Stale,
    PermissionDenied,
    ScanLimit,
    DockerUnavailable,
    NoMatchingSocket,
    UnsupportedTransport,
    MultipleCandidates,
    Truncated,
    QueryLimit,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct ApplicationAttribution {
    pub applications: Vec<ApplicationEvidence>,
    pub reasons: Vec<ApplicationReason>,
}

impl Default for ApplicationAttribution {
    fn default() -> Self {
        Self::unknown(ApplicationReason::NotCollected)
    }
}

impl ApplicationAttribution {
    pub fn unknown(reason: ApplicationReason) -> Self {
        Self {
            applications: vec![],
            reasons: vec![reason],
        }
    }

    pub fn reason(&mut self, reason: ApplicationReason) {
        if !self.reasons.contains(&reason) {
            self.reasons.push(reason);
            self.reasons.sort();
        }
    }

    pub fn add(&mut self, evidence: ApplicationEvidence) {
        if let Some(old) = self.applications.iter_mut().find(|old| {
            old.id == evidence.id
                && old.method == evidence.method
                && old.name == evidence.name
                && old.executable == evidence.executable
                && old.service == evidence.service
                && old.container_id == evidence.container_id
        }) {
            old.observed_from = old.observed_from.min(evidence.observed_from);
            old.observed_to = old.observed_to.max(evidence.observed_to);
        } else if self.applications.len() < APPLICATION_LIMIT {
            self.applications.push(evidence);
            self.applications.sort_by(|a, b| {
                (
                    &a.id,
                    &a.method,
                    &a.name,
                    &a.executable,
                    &a.service,
                    &a.container_id,
                )
                    .cmp(&(
                        &b.id,
                        &b.method,
                        &b.name,
                        &b.executable,
                        &b.service,
                        &b.container_id,
                    ))
            });
        } else {
            self.reason(ApplicationReason::Truncated);
        }
        if self.applications.len() > 1 {
            self.reason(ApplicationReason::MultipleCandidates);
        }
        self.bound();
    }

    pub fn merge(&mut self, other: &Self) {
        for reason in &other.reasons {
            self.reason(*reason);
        }
        for evidence in &other.applications {
            self.add(evidence.clone());
        }
        self.bound();
    }

    fn bound(&mut self) {
        // JSON escaping can expand names; byte bounds complement candidate and
        // text bounds and keep enrichment from failing a traffic transaction.
        while serde_json::to_vec(self).is_ok_and(|s| s.len() > APPLICATION_BYTE_LIMIT)
            && !self.applications.is_empty()
        {
            self.applications.pop();
            self.reason(ApplicationReason::Truncated);
        }
    }
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct ApplicationHealth {
    pub enabled: bool,
    pub state: String,
    pub last_scan: Option<i64>,
    pub sockets: usize,
    #[serde(default)]
    pub owned_sockets: usize,
    #[serde(default)]
    pub diagnostics: Vec<String>,
    pub reasons: Vec<ApplicationReason>,
}

/// Bound untrusted process/container names by UTF-8 bytes without splitting a character.
pub fn application_text(value: &str) -> String {
    let mut end = value.len().min(APPLICATION_TEXT_LIMIT);
    while !value.is_char_boundary(end) {
        end -= 1;
    }
    value[..end].chars().filter(|c| !c.is_control()).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn historical_merge_preserves_changes_and_bounds_candidates() {
        let mut attribution = ApplicationAttribution {
            applications: vec![],
            reasons: vec![],
        };
        for i in 0..12 {
            attribution.add(ApplicationEvidence {
                id: format!("process-{i}"),
                name: format!("app-{i}"),
                method: ApplicationMethod::SocketOwner,
                pid: Some(i),
                process_start: Some(1),
                executable: None,
                service: None,
                container_id: None,
                observed_from: 10,
                observed_to: 20,
            });
        }
        assert_eq!(attribution.applications.len(), APPLICATION_LIMIT);
        assert!(attribution.reasons.contains(&ApplicationReason::Truncated));
        let mut later = attribution.clone();
        later.applications[0].observed_to = 30;
        later.reason(ApplicationReason::PermissionDenied);
        attribution.merge(&later);
        assert_eq!(attribution.applications[0].observed_to, 30);
        assert!(
            attribution
                .reasons
                .contains(&ApplicationReason::PermissionDenied)
        );
        assert!(application_text(&"é".repeat(100)).len() <= APPLICATION_TEXT_LIMIT);
    }

    #[test]
    fn escaped_metadata_is_bounded_in_serialized_bytes() {
        let mut attribution = ApplicationAttribution {
            applications: vec![],
            reasons: vec![],
        };
        for i in 0..8 {
            attribution.add(ApplicationEvidence {
                id: format!("{i}{}", "\\".repeat(250)),
                name: "\\".repeat(128),
                method: ApplicationMethod::SocketOwner,
                pid: Some(i),
                process_start: Some(123),
                executable: Some("\\".repeat(128)),
                service: Some("\\".repeat(128)),
                container_id: Some("\\".repeat(128)),
                observed_from: 0,
                observed_to: i64::MAX,
            });
        }
        assert!(serde_json::to_vec(&attribution).unwrap().len() <= APPLICATION_BYTE_LIMIT);
        assert!(attribution.reasons.contains(&ApplicationReason::Truncated));
    }

    #[test]
    fn exec_or_container_rename_preserves_old_name_for_same_identity() {
        let mut a = ApplicationAttribution {
            applications: vec![],
            reasons: vec![],
        };
        let mut evidence = ApplicationEvidence {
            id: "process:1:100".into(),
            name: "nginx".into(),
            method: ApplicationMethod::SocketOwner,
            pid: Some(1),
            process_start: Some(100),
            executable: None,
            service: None,
            container_id: None,
            observed_from: 100,
            observed_to: 100,
        };
        a.add(evidence.clone());
        evidence.name = "caddy".into();
        evidence.observed_from = 200;
        evidence.observed_to = 200;
        a.add(evidence);
        assert_eq!(a.applications.len(), 2);
        assert!(
            a.applications
                .iter()
                .any(|e| e.name == "nginx" && e.observed_to == 100)
        );
        assert!(
            a.applications
                .iter()
                .any(|e| e.name == "caddy" && e.observed_from == 200)
        );
    }
}
