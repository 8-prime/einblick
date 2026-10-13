//! Only two Docker discovery GETs are issued. No Docker mutation or exec API.
use super::{PublishedEndpoint, SOCKET_LIMIT};
use anyhow::{Context, Result, ensure};
use einblick_core::{ApplicationEvidence, ApplicationMethod, application_text, unix_now};
use http_body_util::{BodyExt, Empty};
use hyper::{Request, body::Bytes};
use hyper_util::rt::TokioIo;
use serde::Deserialize;
use std::{net::IpAddr, time::Duration};
use tokio::net::UnixStream;

struct ConnectionGuard(tokio::task::JoinHandle<Result<(), hyper::Error>>);
impl Drop for ConnectionGuard {
    fn drop(&mut self) {
        self.0.abort();
    }
}

#[derive(Deserialize)]
struct Version {
    #[serde(rename = "ApiVersion")]
    api_version: String,
}

#[derive(Deserialize)]
struct Container {
    #[serde(rename = "Id")]
    id: String,
    #[serde(rename = "Names", default)]
    names: Vec<String>,
    #[serde(rename = "Ports", default)]
    ports: Vec<Port>,
    #[serde(rename = "Labels", default)]
    labels: Labels,
    #[serde(rename = "NetworkSettings", default)]
    network_settings: NetworkSettings,
}

#[derive(Default, Deserialize)]
struct Labels {
    #[serde(rename = "com.docker.compose.service")]
    service: Option<String>,
}

#[derive(Deserialize)]
struct Port {
    #[serde(rename = "IP", default)]
    ip: String,
    #[serde(rename = "PrivatePort")]
    private: u16,
    #[serde(rename = "PublicPort")]
    public: Option<u16>,
    #[serde(rename = "Type")]
    protocol: String,
}

#[derive(Default, Deserialize)]
struct NetworkSettings {
    #[serde(rename = "Networks", default)]
    networks: std::collections::BTreeMap<String, Network>,
}

#[derive(Deserialize)]
struct Network {
    #[serde(rename = "IPAddress", default)]
    address: String,
    #[serde(rename = "GlobalIPv6Address", default)]
    ipv6: String,
}

async fn get(socket: &str, path: &str) -> Result<Vec<u8>> {
    let stream = UnixStream::connect(socket)
        .await
        .context("connect Docker discovery socket")?;
    let (mut sender, connection) =
        hyper::client::conn::http1::handshake(TokioIo::new(stream)).await?;
    let _task = ConnectionGuard(tokio::spawn(connection));
    async {
        let request = Request::builder()
            .uri(path)
            .header("Host", "localhost")
            .body(Empty::<Bytes>::new())?;
        let response = sender.send_request(request).await?;
        ensure!(
            response.status().is_success(),
            "Docker discovery request failed"
        );
        let mut body = response.into_body();
        let mut bytes = vec![];
        while let Some(frame) = body.frame().await {
            let frame = frame?;
            if let Ok(data) = frame.into_data() {
                ensure!(
                    bytes.len() + data.len() <= 4 * 1024 * 1024,
                    "Docker response exceeds limit"
                );
                bytes.extend_from_slice(&data);
            }
        }
        Ok(bytes)
    }
    .await
}

pub(super) async fn discover(socket: &str) -> Result<Vec<PublishedEndpoint>> {
    tokio::time::timeout(Duration::from_secs(3), async {
        let version: Version = serde_json::from_slice(&get(socket, "/version").await?)?;
        ensure!(
            version.api_version.len() <= 12
                && version.api_version.split('.').count() == 2
                && version
                    .api_version
                    .split('.')
                    .all(|s| !s.is_empty() && s.bytes().all(|b| b.is_ascii_digit())),
            "invalid Docker API version"
        );
        let bytes = get(
            socket,
            &format!("/v{}/containers/json", version.api_version),
        )
        .await?;
        endpoints(&bytes, unix_now())
    })
    .await
    .context("Docker discovery timeout")?
}

fn endpoints(bytes: &[u8], observed: i64) -> Result<Vec<PublishedEndpoint>> {
    let containers: Vec<Container> = serde_json::from_slice(bytes)?;
    ensure!(
        containers.len() <= 1024,
        "Docker container count exceeds limit"
    );
    let mut endpoints = vec![];
    for container in containers {
        ensure!(
            container.id.len() == 64 && container.id.bytes().all(|b| b.is_ascii_hexdigit()),
            "invalid Docker container ID"
        );
        let application = ApplicationEvidence {
            id: format!("docker:{}", container.id),
            name: application_text(
                container
                    .names
                    .first()
                    .map(|n| n.trim_start_matches('/'))
                    .unwrap_or(&container.id[..12]),
            ),
            method: ApplicationMethod::PublishedPort,
            pid: None,
            process_start: None,
            executable: None,
            service: container.labels.service.map(|s| application_text(&s)),
            container_id: Some(container.id),
            observed_from: observed,
            observed_to: observed,
        };
        for port in container.ports {
            let protocol = match port.protocol.as_str() {
                "tcp" => 6,
                "udp" => 17,
                _ => continue,
            };
            if let Some(public) = port.public {
                let address: IpAddr = if port.ip.is_empty() {
                    "0.0.0.0".parse()?
                } else {
                    port.ip.parse()?
                };
                endpoints.push(PublishedEndpoint {
                    address,
                    port: public,
                    protocol,
                    application: application.clone(),
                });
            }
            // Direct-routed/exposed endpoints must match the actual container IP,
            // not a wildcard host listener on the same private port.
            for network in container.network_settings.networks.values() {
                for address in [&network.address, &network.ipv6]
                    .into_iter()
                    .filter(|s| !s.is_empty())
                {
                    endpoints.push(PublishedEndpoint {
                        address: address.parse()?,
                        port: port.private,
                        protocol,
                        application: application.clone(),
                    });
                }
            }
            ensure!(
                endpoints.len() <= SOCKET_LIMIT,
                "Docker endpoint count exceeds limit"
            );
        }
    }
    Ok(endpoints)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn resolves_public_and_private_ports_without_confusing_protocols() {
        let data = serde_json::json!([{"Id":"a".repeat(64),"Names":["/web-1"],
            "Labels":{"com.docker.compose.service":"web","unrelated":"ignored"},
            "Ports":[{"IP":"0.0.0.0","PrivatePort":80,"PublicPort":8080,"Type":"tcp"},
                {"IP":"::","PrivatePort":53,"PublicPort":5353,"Type":"udp"}],
            "NetworkSettings":{"Networks":{"default":{"IPAddress":"172.18.0.2","GlobalIPv6Address":"fd00::2"}}}}]);
        let endpoints = endpoints(&serde_json::to_vec(&data).unwrap(), 123).unwrap();
        assert!(
            endpoints
                .iter()
                .any(|e| e.address == "0.0.0.0".parse::<IpAddr>().unwrap()
                    && e.port == 8080
                    && e.protocol == 6)
        );
        assert!(
            endpoints
                .iter()
                .any(|e| e.address == "172.18.0.2".parse::<IpAddr>().unwrap() && e.port == 80)
        );
        assert!(
            endpoints
                .iter()
                .any(|e| e.address == "::".parse::<IpAddr>().unwrap()
                    && e.port == 5353
                    && e.protocol == 17)
        );
        assert!(
            endpoints
                .iter()
                .all(|e| e.application.name == "web-1" && e.application.observed_from == 123)
        );
    }
}
