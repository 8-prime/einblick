//! Optional DB-IP Lite context. This is independent of capture and enforcement.
use anyhow::{Context, Result, ensure};
use chrono::{Datelike, Months, Utc};
use einblick_core::{Config, IpDatabaseHealth, IpEnrichmentHealth, IpInfo, unix_now};
use flate2::read::GzDecoder;
use maxminddb::Reader;
use serde::Deserialize;
use std::{
    collections::BTreeMap,
    io::{Read, Write},
    net::IpAddr,
    path::{Path, PathBuf},
    sync::{Arc, RwLock},
    time::Duration,
};
use tokio::sync::broadcast;

const MAX_DOWNLOAD: usize = 32 * 1024 * 1024;
const MAX_DATABASE: usize = 64 * 1024 * 1024;
type Database = Reader<Vec<u8>>;

#[derive(Clone, Copy)]
enum Kind {
    Country,
    Asn,
}
impl Kind {
    fn name(self) -> &'static str {
        match self {
            Self::Country => "country",
            Self::Asn => "asn",
        }
    }
    fn database_type(self) -> &'static str {
        match self {
            Self::Country => "DBIP-Country-Lite",
            Self::Asn => "DBIP-ASN-Lite",
        }
    }
    fn path(self, directory: &Path) -> PathBuf {
        directory.join(format!("dbip-{}-lite.mmdb", self.name()))
    }
    fn url(self, release: &str) -> String {
        format!(
            "https://download.db-ip.com/free/dbip-{}-lite-{release}.mmdb.gz",
            self.name()
        )
    }
}

#[derive(Default)]
struct State {
    country: Option<Arc<Database>>,
    asn: Option<Arc<Database>>,
    health: IpEnrichmentHealth,
}

#[derive(Clone, Default)]
pub struct Enrichment(Arc<RwLock<State>>);
impl Enrichment {
    pub fn start(config: &Config, mut shutdown: broadcast::Receiver<()>) -> Self {
        let service = Self::default();
        let enabled = config.ip_enrichment.enabled && !config.mock;
        service.0.write().unwrap().health = IpEnrichmentHealth {
            enabled,
            state: if enabled { "waiting" } else { "disabled" }.into(),
            ..Default::default()
        };
        if enabled {
            let directory = if config.ip_enrichment.directory.is_empty() {
                Path::new(&config.database)
                    .parent()
                    .unwrap_or(Path::new("."))
                    .join("ip-enrichment")
            } else {
                PathBuf::from(&config.ip_enrichment.directory)
            };
            let updater = service.clone();
            let seconds = config.ip_enrichment.check_seconds;
            tokio::spawn(async move {
                tokio::select! {
                    _ = shutdown.recv() => {},
                    result = updater.run(directory, seconds) => {
                        if let Err(error) = result {
                            let mut state = updater.0.write().unwrap();
                            state.health.last_error = Some(error.to_string());
                            state.health.state = "unavailable".into();
                            tracing::warn!(%error, "IP enrichment updater stopped");
                        }
                    }
                }
            });
        }
        service
    }

    pub fn health(&self) -> IpEnrichmentHealth {
        let mut health = self.0.read().unwrap().health.clone();
        if health.enabled && health.state != "waiting" && health.state != "downloading" {
            let current = release_months().0;
            health.state = match (&health.country.release, &health.asn.release) {
                (Some(a), Some(b)) if a == &current && b == &current => "ready",
                (Some(_), Some(_)) => "stale",
                (None, None) => "unavailable",
                _ => "partial",
            }
            .into();
        }
        health
    }

    pub fn lookup(&self, ip: IpAddr) -> Option<IpInfo> {
        let ip = ip.to_canonical();
        if !public_address(ip) {
            return None;
        }
        let (country, asn) = {
            let state = self.0.read().unwrap();
            (state.country.clone(), state.asn.clone())
        };
        let country = country
            .as_ref()
            .and_then(|db| db.lookup(ip).ok()?.decode::<CountryRecord>().ok().flatten());
        let asn = asn
            .as_ref()
            .and_then(|db| db.lookup(ip).ok()?.decode::<AsnRecord>().ok().flatten());
        let info = IpInfo {
            country_code: country
                .as_ref()
                .and_then(|c| c.country.iso_code.clone())
                .filter(|s| s.len() == 2 && s.bytes().all(|b| b.is_ascii_uppercase())),
            country: country
                .and_then(|mut c| c.country.names.remove("en"))
                .map(clean_text),
            asn: asn
                .as_ref()
                .and_then(|a| a.autonomous_system_number)
                .filter(|n| *n > 0),
            organization: asn
                .and_then(|a| a.autonomous_system_organization)
                .map(clean_text),
        };
        (info != IpInfo::default()).then_some(info)
    }

    fn install(&self, kind: Kind, reader: Database) {
        let metadata = reader.metadata();
        let health = IpDatabaseHealth {
            release: chrono::DateTime::from_timestamp(metadata.build_epoch as i64, 0)
                .map(|date| date.format("%Y-%m").to_string()),
            build_at: Some(metadata.build_epoch as i64),
        };
        let mut state = self.0.write().unwrap();
        match kind {
            Kind::Country => {
                state.country = Some(Arc::new(reader));
                state.health.country = health;
            }
            Kind::Asn => {
                state.asn = Some(Arc::new(reader));
                state.health.asn = health;
            }
        }
    }

    async fn run(&self, directory: PathBuf, seconds: u64) -> Result<()> {
        let client = reqwest::Client::builder()
            .https_only(true)
            .connect_timeout(Duration::from_secs(15))
            .timeout(Duration::from_secs(180))
            .user_agent(concat!("Einblick/", env!("CARGO_PKG_VERSION")))
            .build()?;
        // File reads and full MMDB validation never run on the capture threads.
        for kind in [Kind::Country, Kind::Asn] {
            let path = kind.path(&directory);
            let result = tokio::task::spawn_blocking(move || load_database(&path, kind)).await?;
            match result {
                Ok(Some(reader)) => self.install(kind, reader),
                Ok(None) => {}
                Err(error) => {
                    tracing::warn!(%error, database=kind.name(), "Ignoring invalid cached IP database")
                }
            }
        }
        let mut timer = tokio::time::interval(Duration::from_secs(seconds));
        timer.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        loop {
            timer.tick().await;
            {
                let mut state = self.0.write().unwrap();
                state.health.state = "downloading".into();
                state.health.last_check = Some(unix_now());
            }
            let mut errors = vec![];
            for kind in [Kind::Country, Kind::Asn] {
                if let Err(error) = self.update(&client, &directory, kind).await {
                    tracing::warn!(%error, database=kind.name(), "IP database update failed; retaining previous data");
                    errors.push(format!("{}: {error:#}", kind.name()));
                }
            }
            let mut state = self.0.write().unwrap();
            state.health.state = "checked".into();
            state.health.last_error = (!errors.is_empty()).then(|| errors.join("; "));
        }
    }

    async fn update(&self, client: &reqwest::Client, directory: &Path, kind: Kind) -> Result<()> {
        self.update_from(client, directory, kind, |release| kind.url(release))
            .await
    }

    async fn update_from(
        &self,
        client: &reqwest::Client,
        directory: &Path,
        kind: Kind,
        url: impl Fn(&str) -> String,
    ) -> Result<()> {
        let health = self.health();
        let loaded = match kind {
            Kind::Country => health.country.release,
            Kind::Asn => health.asn.release,
        };
        let (current, previous) = release_months();
        // A monthly release may not be published yet. Try last month only on 404.
        for release in [current, previous] {
            if loaded.as_ref().is_some_and(|cached| cached >= &release) {
                return Ok(());
            }
            let response = client
                .get(url(&release))
                .send()
                .await
                .context("download DB-IP Lite")?;
            if response.status() == reqwest::StatusCode::NOT_FOUND {
                continue;
            }
            let compressed = download_body(response.error_for_status()?).await?;
            let path = kind.path(directory);
            let reader = tokio::task::spawn_blocking(move || {
                install_download(&path, kind, &release, &compressed)
            })
            .await??;
            self.install(kind, reader);
            return Ok(());
        }
        anyhow::bail!("current and previous monthly releases unavailable")
    }
}

fn release_months() -> (String, String) {
    let now = Utc::now().date_naive();
    let first = now.with_day(1).unwrap();
    (
        first.format("%Y-%m").to_string(),
        first
            .checked_sub_months(Months::new(1))
            .unwrap()
            .format("%Y-%m")
            .to_string(),
    )
}

async fn download_body(mut response: reqwest::Response) -> Result<Vec<u8>> {
    ensure!(
        response
            .content_length()
            .is_none_or(|size| size <= MAX_DOWNLOAD as u64),
        "compressed database exceeds size limit"
    );
    let mut bytes = Vec::new();
    while let Some(chunk) = response.chunk().await? {
        ensure!(
            bytes.len().saturating_add(chunk.len()) <= MAX_DOWNLOAD,
            "compressed database exceeds size limit"
        );
        bytes.extend_from_slice(&chunk);
    }
    Ok(bytes)
}

fn validate(reader: &Reader<impl AsRef<[u8]>>, kind: Kind) -> Result<()> {
    ensure!(
        reader.metadata().database_type == kind.database_type()
            || (matches!(kind, Kind::Asn)
                && reader.metadata().database_type == "DBIP-ASN-Lite (compat=GeoLite2-ASN)"),
        "unexpected MMDB database type: expected {}, got {:?}",
        kind.database_type(),
        reader.metadata().database_type
    );
    ensure!(
        reader.metadata().ip_version == 6,
        "database must support IPv4 and IPv6"
    );
    ensure!(
        reader.metadata().build_epoch <= unix_now() as u64 + 86400,
        "database build date is in the future"
    );
    reader.verify().context("validate MMDB contents")?;
    Ok(())
}

fn load_database(path: &Path, kind: Kind) -> Result<Option<Database>> {
    let metadata = match std::fs::metadata(path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(error.into()),
    };
    ensure!(
        metadata.len() <= MAX_DATABASE as u64,
        "cached database exceeds size limit"
    );
    let reader = Reader::open_readfile(path)?;
    validate(&reader, kind)?;
    Ok(Some(reader))
}

fn install_download(path: &Path, kind: Kind, release: &str, compressed: &[u8]) -> Result<Database> {
    let mut bytes = Vec::new();
    GzDecoder::new(compressed)
        .take(MAX_DATABASE as u64 + 1)
        .read_to_end(&mut bytes)
        .context("decompress DB-IP Lite")?;
    ensure!(
        bytes.len() <= MAX_DATABASE,
        "decompressed database exceeds size limit"
    );
    let reader = Reader::from_source(bytes.as_slice())?;
    validate(&reader, kind)?;
    let build = chrono::DateTime::from_timestamp(reader.metadata().build_epoch as i64, 0)
        .context("invalid database build date")?;
    ensure!(
        build.format("%Y-%m").to_string() == release,
        "database build date does not match requested release"
    );
    let directory = path.parent().context("missing database directory")?;
    std::fs::create_dir_all(directory)?;
    let temporary = path.with_extension("mmdb.part");
    let mut file = std::fs::File::create(&temporary)?;
    file.write_all(&bytes)?;
    file.sync_all()?;
    std::fs::rename(&temporary, path).context("replace cached database")?;
    std::fs::File::open(directory)?.sync_all()?;
    Ok(Reader::from_source(bytes)?)
}

#[derive(Default, Deserialize)]
#[serde(default)]
struct CountryRecord {
    country: Country,
}
#[derive(Default, Deserialize)]
#[serde(default)]
struct Country {
    iso_code: Option<String>,
    names: BTreeMap<String, String>,
}
#[derive(Default, Deserialize)]
#[serde(default)]
struct AsnRecord {
    autonomous_system_number: Option<u32>,
    autonomous_system_organization: Option<String>,
}

fn clean_text(text: String) -> String {
    text.chars().filter(|c| !c.is_control()).take(256).collect()
}

fn public_address(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(ip) => {
            let [a, b, c, _] = ip.octets();
            !(matches!(a, 0 | 10 | 127)
                || a >= 224
                || (a == 100 && (64..=127).contains(&b))
                || (a == 169 && b == 254)
                || (a == 172 && (16..=31).contains(&b))
                || (a == 192 && (b == 168 || (b == 0 && matches!(c, 0 | 2))))
                || (a == 198 && (matches!(b, 18 | 19) || (b == 51 && c == 100)))
                || (a == 203 && b == 0 && c == 113))
        }
        IpAddr::V6(ip) => {
            let s = ip.segments();
            s[0] & 0xe000 == 0x2000 && !(s[0] == 0x2001 && s[1] == 0x0db8)
        }
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use flate2::{Compression, write::GzEncoder};
    use serde_json::{Value, json};

    // A tiny valid IPv6 MMDB with one record shared by both root branches.
    // Fixtures stay deterministic and never require provider/network access.
    fn encode(value: &Value, out: &mut Vec<u8>) {
        fn control(out: &mut Vec<u8>, kind: u8, len: usize) {
            assert!(len < 285);
            out.push((kind.min(7) << 5) | len.min(29) as u8);
            if kind > 7 {
                *out.last_mut().unwrap() &= 31;
                out.push(kind - 7);
            }
            if len >= 29 {
                out.push((len - 29) as u8);
            }
        }
        match value {
            Value::String(s) => {
                control(out, 2, s.len());
                out.extend(s.as_bytes());
            }
            Value::Number(n) => {
                control(out, 6, 4);
                out.extend((n.as_u64().unwrap() as u32).to_be_bytes());
            }
            Value::Array(a) => {
                control(out, 11, a.len());
                for v in a {
                    encode(v, out);
                }
            }
            Value::Object(map) => {
                control(out, 7, map.len());
                for (key, value) in map {
                    encode(&Value::String(key.clone()), out);
                    if matches!(
                        key.as_str(),
                        "binary_format_major_version"
                            | "binary_format_minor_version"
                            | "ip_version"
                            | "record_size"
                    ) {
                        control(out, 5, 2);
                        out.extend((value.as_u64().unwrap() as u16).to_be_bytes());
                    } else if key == "build_epoch" {
                        control(out, 9, 8);
                        out.extend(value.as_u64().unwrap().to_be_bytes());
                    } else {
                        encode(value, out);
                    }
                }
            }
            _ => panic!("unsupported fixture value"),
        }
    }
    fn fixture(kind: Kind) -> Vec<u8> {
        fixture_at(kind, unix_now())
    }
    fn fixture_at(kind: Kind, build_at: i64) -> Vec<u8> {
        let mut bytes = vec![0, 0, 17, 0, 0, 17];
        bytes.extend([0; 16]);
        let record = match kind {
            Kind::Country => json!({"country":{"iso_code":"RO","names":{"en":"Romania"}}}),
            Kind::Asn => {
                json!({"autonomous_system_number":64512,"autonomous_system_organization":"Example network"})
            }
        };
        encode(&record, &mut bytes);
        bytes.extend(b"\xab\xcd\xefMaxMind.com");
        encode(
            &json!({
                "binary_format_major_version":2,"binary_format_minor_version":0,
                "build_epoch":build_at,"database_type":kind.database_type(),
                "description":{"en":"Einblick test fixture"},"ip_version":6,
                "languages":["en"],"node_count":1,"record_size":24
            }),
            &mut bytes,
        );
        bytes
    }
    fn compressed(bytes: &[u8]) -> Vec<u8> {
        let mut encoder = GzEncoder::new(Vec::new(), Compression::default());
        encoder.write_all(bytes).unwrap();
        encoder.finish().unwrap()
    }
    fn directory() -> PathBuf {
        let directory =
            std::env::temp_dir().join(format!("einblick-enrichment-{:x}", rand::random::<u64>()));
        std::fs::create_dir_all(&directory).unwrap();
        directory
    }

    pub(crate) fn fixture_enrichment() -> Enrichment {
        let enrichment = Enrichment::default();
        for kind in [Kind::Country, Kind::Asn] {
            enrichment.install(kind, Reader::from_source(fixture(kind)).unwrap());
        }
        enrichment
    }

    async fn http_server(
        responses: Vec<(u16, Vec<u8>)>,
    ) -> (String, tokio::task::JoinHandle<Vec<String>>) {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let task = tokio::spawn(async move {
            let mut requests = vec![];
            for (status, body) in responses {
                let (mut socket, _) = listener.accept().await.unwrap();
                let mut request = vec![];
                let mut byte = [0];
                while !request.ends_with(b"\r\n\r\n") {
                    socket.read_exact(&mut byte).await.unwrap();
                    request.push(byte[0]);
                }
                requests.push(String::from_utf8(request).unwrap());
                socket.write_all(format!("HTTP/1.1 {status} Test\r\nContent-Length: {}\r\nConnection: close\r\n\r\n", body.len()).as_bytes()).await.unwrap();
                socket.write_all(&body).await.unwrap();
            }
            requests
        });
        (format!("http://{address}"), task)
    }

    #[tokio::test]
    async fn monthly_fallback_download_failure_and_current_cache_skip() {
        let directory = directory();
        let service = Enrichment::default();
        let client = reqwest::Client::builder()
            .timeout(Duration::from_secs(5))
            .build()
            .unwrap();
        let (current, previous) = release_months();
        let build = chrono::NaiveDate::parse_from_str(&format!("{previous}-01"), "%Y-%m-%d")
            .unwrap()
            .and_hms_opt(0, 0, 0)
            .unwrap()
            .and_utc()
            .timestamp();
        let good = compressed(&fixture_at(Kind::Country, build));
        let (url, task) = http_server(vec![(404, vec![]), (200, good)]).await;
        service
            .update_from(&client, &directory, Kind::Country, |release| {
                format!("{url}/{release}")
            })
            .await
            .unwrap();
        let requests = task.await.unwrap();
        assert!(requests[0].starts_with(&format!("GET /{current} ")));
        assert!(requests[1].starts_with(&format!("GET /{previous} ")));
        assert_eq!(
            service.health().country.release.as_deref(),
            Some(previous.as_str())
        );
        let path = Kind::Country.path(&directory);
        let original = std::fs::read(&path).unwrap();
        let (url, task) = http_server(vec![(200, b"corrupt gzip".to_vec())]).await;
        assert!(
            service
                .update_from(&client, &directory, Kind::Country, |_| url.clone())
                .await
                .is_err()
        );
        task.await.unwrap();
        assert_eq!(std::fs::read(&path).unwrap(), original);
        assert_eq!(
            service
                .lookup("8.8.8.8".parse().unwrap())
                .unwrap()
                .country_code
                .as_deref(),
            Some("RO")
        );
        service.install(
            Kind::Country,
            Reader::from_source(fixture(Kind::Country)).unwrap(),
        );
        service
            .update_from(&client, &directory, Kind::Country, |_| {
                panic!("unexpected download")
            })
            .await
            .unwrap();
        std::fs::remove_dir_all(directory).unwrap();
    }

    #[tokio::test]
    #[ignore = "Downloads public monthly databases over HTTPS"]
    async fn live_background_downloads_and_restart() {
        let directory = directory();
        let mut config = Config::default();
        config.ip_enrichment.directory = directory.to_string_lossy().into();
        let (shutdown, _) = broadcast::channel(1);
        let service = Enrichment::start(&config, shutdown.subscribe());
        tokio::time::timeout(Duration::from_secs(60), async {
            loop {
                let health = service.health();
                assert!(health.last_error.is_none(), "{:?}", health.last_error);
                if health.state == "ready" {
                    break;
                }
                tokio::time::sleep(Duration::from_millis(100)).await;
            }
        })
        .await
        .unwrap();
        assert_eq!(
            service.lookup("8.8.8.8".parse().unwrap()).unwrap().asn,
            Some(15169)
        );
        shutdown.send(()).unwrap();
        let restarted = Enrichment::start(&config, shutdown.subscribe());
        tokio::time::timeout(Duration::from_secs(15), async {
            while restarted.health().state != "ready" {
                tokio::time::sleep(Duration::from_millis(50)).await;
            }
        })
        .await
        .unwrap();
        assert_eq!(
            restarted.lookup("8.8.8.8".parse().unwrap()),
            service.lookup("8.8.8.8".parse().unwrap())
        );
        shutdown.send(()).unwrap();
        std::fs::remove_dir_all(directory).unwrap();
    }

    #[test]
    fn country_asn_ipv4_ipv6_and_reserved_addresses() {
        let enrichment = Enrichment::default();
        for kind in [Kind::Country, Kind::Asn] {
            let reader = Reader::from_source(fixture(kind)).unwrap();
            validate(&reader, kind).unwrap();
            enrichment.install(kind, reader);
        }
        for ip in ["8.8.8.8", "2001:4860:4860::8888", "::ffff:8.8.8.8"] {
            let info = enrichment.lookup(ip.parse().unwrap()).unwrap();
            assert_eq!(info.country.as_deref(), Some("Romania"));
            assert_eq!(info.country_code.as_deref(), Some("RO"));
            assert_eq!(info.asn, Some(64512));
            assert_eq!(info.organization.as_deref(), Some("Example network"));
        }
        for ip in [
            "127.0.0.1",
            "10.0.0.1",
            "192.168.1.1",
            "100.64.0.1",
            "192.0.2.1",
            "224.0.0.1",
            "::",
            "::1",
            "fc00::1",
            "fe80::1",
            "2001:db8::1",
            "::ffff:10.0.0.1",
        ] {
            assert!(enrichment.lookup(ip.parse().unwrap()).is_none(), "{ip}");
        }
    }

    #[test]
    fn atomic_install_restart_and_rejected_updates_preserve_cache() {
        let directory = directory();
        let path = Kind::Country.path(&directory);
        let release = release_months().0;
        let good = compressed(&fixture(Kind::Country));
        let reader = install_download(&path, Kind::Country, &release, &good).unwrap();
        let original = std::fs::read(&path).unwrap();
        for bad in [
            compressed(b"not MMDB"),
            compressed(&fixture(Kind::Asn)),
            b"truncated gzip".to_vec(),
        ] {
            assert!(install_download(&path, Kind::Country, &release, &bad).is_err());
            assert_eq!(std::fs::read(&path).unwrap(), original);
        }
        assert!(install_download(&path, Kind::Country, "2000-01", &good).is_err());
        assert_eq!(std::fs::read(&path).unwrap(), original);
        let enrichment = Enrichment::default();
        enrichment.install(Kind::Country, reader);
        let restarted = Enrichment::default();
        restarted.install(
            Kind::Country,
            load_database(&path, Kind::Country).unwrap().unwrap(),
        );
        let ip = "8.8.8.8".parse().unwrap();
        assert_eq!(enrichment.lookup(ip), restarted.lookup(ip));
        assert!(
            load_database(&Kind::Asn.path(&directory), Kind::Asn)
                .unwrap()
                .is_none()
        );
        std::fs::remove_dir_all(directory).unwrap();
    }

    #[tokio::test]
    async fn mock_and_disabled_modes_do_not_start_downloads() {
        let directory = directory().join("never-created");
        let mut config = Config {
            mock: true,
            ..Default::default()
        };
        config.ip_enrichment.directory = directory.to_string_lossy().into();
        let (shutdown, _) = broadcast::channel(1);
        let service = Enrichment::start(&config, shutdown.subscribe());
        assert!(!service.health().enabled);
        assert_eq!(service.health().state, "disabled");
        config.mock = false;
        config.ip_enrichment.enabled = false;
        let service = Enrichment::start(&config, shutdown.subscribe());
        assert!(!service.health().enabled);
        assert!(!directory.exists());
        std::fs::remove_dir_all(directory.parent().unwrap()).unwrap();
    }

    #[test]
    #[ignore = "Requires downloaded DB-IP files; set EINBLICK_DBIP_DOWNLOAD_DIR"]
    fn real_dbip_downloads_validate_and_lookup() {
        let downloads = PathBuf::from(std::env::var("EINBLICK_DBIP_DOWNLOAD_DIR").unwrap());
        let directory = directory();
        let enrichment = Enrichment::default();
        for kind in [Kind::Country, Kind::Asn] {
            let bytes =
                std::fs::read(downloads.join(format!("einblick-dbip-{}.mmdb.gz", kind.name())))
                    .unwrap();
            let reader =
                install_download(&kind.path(&directory), kind, &release_months().0, &bytes)
                    .unwrap();
            enrichment.install(kind, reader);
        }
        for ip in ["8.8.8.8", "2001:4860:4860::8888"] {
            let info = enrichment.lookup(ip.parse().unwrap()).unwrap();
            assert_eq!(info.asn, Some(15169));
            assert!(
                info.country_code
                    .as_ref()
                    .is_some_and(|code| code.len() == 2)
            );
            assert!(info.country.as_ref().is_some_and(|name| !name.is_empty()));
        }
        std::fs::remove_dir_all(directory).unwrap();
    }
}
