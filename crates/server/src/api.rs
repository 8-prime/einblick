use crate::{
    auth::Auth,
    monitor::{Action, Command},
};
use axum::{
    Json, Router,
    body::Body,
    extract::{ConnectInfo, DefaultBodyLimit, Path, Query, State},
    http::{HeaderMap, Method, Request, StatusCode, header},
    middleware::{self, Next},
    response::{
        IntoResponse, Response, Sse,
        sse::{Event, KeepAlive},
    },
    routing::{get, post},
};
use einblick_core::{storage::Database, *};
use ipnet::IpNet;
use rust_embed::RustEmbed;
use serde::Deserialize;
use std::{
    convert::Infallible,
    net::{IpAddr, SocketAddr},
    sync::Arc,
};
use tokio::sync::{RwLock, broadcast, mpsc, oneshot};
use tokio_stream::{StreamExt, wrappers::BroadcastStream};

#[derive(RustEmbed)]
#[folder = "$OUT_DIR/web"]
struct Assets;
#[derive(Clone)]
pub struct App {
    pub config: Arc<Config>,
    pub db: Database,
    pub auth: Arc<Auth>,
    pub snapshot: Arc<RwLock<Snapshot>>,
    pub live_traffic: Arc<RwLock<LiveTraffic>>,
    pub ip_enrichment: crate::ip_enrichment::Enrichment,
    pub commands: mpsc::Sender<Command>,
    pub updates: broadcast::Sender<Snapshot>,
    pub shutdown: broadcast::Sender<()>,
}
#[derive(Debug)]
pub struct ApiError(pub StatusCode, pub String);
impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        (self.0, Json(serde_json::json!({"error":self.1}))).into_response()
    }
}
impl From<anyhow::Error> for ApiError {
    fn from(e: anyhow::Error) -> Self {
        Self(StatusCode::BAD_REQUEST, e.to_string())
    }
}
fn session_id(headers: &HeaderMap) -> Option<&str> {
    headers
        .get(header::COOKIE)?
        .to_str()
        .ok()?
        .split(';')
        .find_map(|c| c.trim().strip_prefix("einblick_session="))
}
fn origin_valid(app: &App, headers: &HeaderMap) -> bool {
    headers.get(header::ORIGIN).and_then(|v| v.to_str().ok())
        == Some(app.config.public_origin.as_str())
}
async fn protect(State(app): State<App>, mut request: Request<Body>, next: Next) -> Response {
    let session = session_id(request.headers()).and_then(|id| app.auth.session(id));
    let Some(session) = session else {
        return ApiError(StatusCode::UNAUTHORIZED, "login required".into()).into_response();
    };
    if request.method() != Method::GET
        && (!origin_valid(&app, request.headers())
            || request
                .headers()
                .get("x-csrf-token")
                .and_then(|v| v.to_str().ok())
                != Some(session.csrf.as_str()))
    {
        return ApiError(StatusCode::FORBIDDEN, "invalid origin or CSRF token".into())
            .into_response();
    }
    request.extensions_mut().insert(session);
    next.run(request).await
}
async fn security(request: Request<Body>, next: Next) -> Response {
    let mut response = next.run(request).await;
    let h = response.headers_mut();
    h.insert("x-content-type-options", "nosniff".parse().unwrap());
    h.insert("referrer-policy", "no-referrer".parse().unwrap());
    h.insert("content-security-policy","default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; connect-src 'self'; img-src 'self' data:; frame-ancestors 'none'; base-uri 'none'; form-action 'self'".parse().unwrap());
    h.insert(header::CACHE_CONTROL, "no-store".parse().unwrap());
    response
}
pub fn router(app: App) -> Router {
    let private = Router::new()
        .route("/auth/session", get(session))
        .route("/auth/logout", post(logout))
        .route("/snapshot", get(snapshot))
        .route("/stream", get(stream))
        .route("/history", get(history))
        .route("/analytics", get(analytics))
        .route("/sources/{ip}/traffic", get(source_traffic))
        .route("/traffic", get(traffic_query))
        .route("/events", get(events))
        .route("/rules", get(rules).post(add_rule))
        .route("/rules/{id}", axum::routing::delete(remove_rule))
        .route("/mode", post(mode))
        .route("/emergency-disable", post(emergency))
        .route_layer(middleware::from_fn_with_state(app.clone(), protect));
    Router::new()
        .nest("/api/v1", private.route("/auth/login", post(login)))
        .route("/healthz", get(health))
        .fallback(asset)
        .layer(DefaultBodyLimit::max(8192))
        .layer(middleware::from_fn(security))
        .with_state(app)
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Login {
    password: String,
}
async fn login(
    State(app): State<App>,
    connect: Option<axum::Extension<ConnectInfo<SocketAddr>>>,
    headers: HeaderMap,
    Json(input): Json<Login>,
) -> Result<Response, ApiError> {
    if !origin_valid(&app, &headers) {
        return Err(ApiError(StatusCode::FORBIDDEN, "invalid origin".into()));
    }
    let peer = connect.map_or("127.0.0.1".parse().unwrap(), |c| c.0.0.ip());
    // Only trusted immediate peers can supply an overwritten X-Real-IP header.
    let ip = if app.config.trusted(peer) {
        headers
            .get("x-real-ip")
            .and_then(|v| v.to_str().ok())
            .and_then(|v| v.parse::<IpAddr>().ok())
            .unwrap_or(peer)
    } else {
        peer
    };
    let Some((id, csrf)) = app.auth.login(ip, input.password).await else {
        return Err(ApiError(
            StatusCode::UNAUTHORIZED,
            "invalid credentials or login rate limit reached".into(),
        ));
    };
    let cookie = format!(
        "einblick_session={id}; HttpOnly; SameSite=Strict; Path=/; Max-Age=43200{}",
        if app.config.secure_cookies {
            "; Secure"
        } else {
            ""
        }
    );
    Ok((
        [(header::SET_COOKIE, cookie)],
        Json(serde_json::json!({"csrf":csrf})),
    )
        .into_response())
}
async fn session(
    State(app): State<App>,
    axum::Extension(s): axum::Extension<crate::auth::Session>,
) -> Json<serde_json::Value> {
    Json(
        serde_json::json!({"csrf":s.csrf,"management_allowlist":app.config.management_allowlist,"thresholds":app.config.detection,
            "detail_limits":{"minute_days":app.config.retention.minute_days,"hourly_days":app.config.retention.hourly_days,"row_limit":app.config.detail_row_limit}}),
    )
}
async fn logout(State(app): State<App>, headers: HeaderMap) -> Response {
    if let Some(id) = session_id(&headers) {
        app.auth.logout(id);
    }
    (
        [(
            header::SET_COOKIE,
            "einblick_session=; HttpOnly; SameSite=Strict; Path=/; Max-Age=0",
        )],
        StatusCode::NO_CONTENT,
    )
        .into_response()
}
async fn snapshot(State(app): State<App>) -> Json<Snapshot> {
    Json(app.snapshot.read().await.clone())
}
async fn rules(State(app): State<App>) -> Json<Vec<Rule>> {
    Json(app.snapshot.read().await.rules.clone())
}
async fn stream(
    State(app): State<App>,
    headers: HeaderMap,
) -> Sse<impl futures_util::Stream<Item = Result<Event, Infallible>>> {
    let auth = app.auth.clone();
    let id = session_id(&headers).unwrap().to_owned();
    let mut shutdown = app.shutdown.subscribe();
    let stream = futures_util::StreamExt::take_while(
        BroadcastStream::new(app.updates.subscribe()),
        move |_| futures_util::future::ready(auth.session(&id).is_some()),
    );
    let stream = stream.filter_map(|item| match item {
        Ok(s) => Some(Ok(Event::default().event("snapshot").json_data(s).unwrap())),
        Err(_) => Some(Ok(Event::default().event("resync").data("{}"))),
    });
    let stream = futures_util::StreamExt::take_until(stream, async move {
        let _ = shutdown.recv().await;
    });
    Sse::new(stream).keep_alive(KeepAlive::default())
}
#[derive(Deserialize)]
struct HistoryQuery {
    resolution: Option<String>,
    from: Option<i64>,
    to: Option<i64>,
}
async fn history(
    State(app): State<App>,
    Query(q): Query<HistoryQuery>,
) -> Result<Json<Vec<Aggregate>>, ApiError> {
    let now = unix_now();
    Ok(Json(
        app.db
            .history(
                q.resolution.unwrap_or("minute".into()),
                q.from.unwrap_or(now - 86400),
                q.to.unwrap_or(now),
            )
            .await?,
    ))
}
#[derive(Deserialize)]
struct EventsQuery {
    limit: Option<u32>,
    before: Option<i64>,
    ip: Option<IpAddr>,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct AnalyticsQuery {
    from: Option<i64>,
    to: Option<i64>,
}
async fn analytics(
    State(app): State<App>,
    Query(q): Query<AnalyticsQuery>,
) -> Result<Json<crate::analytics::Summary>, ApiError> {
    let to = q.to.unwrap_or_else(unix_now);
    let from = q.from.unwrap_or(to - 86400);
    if from < 0 || to < from || to - from > 30 * 86400 {
        return Err(ApiError(
            StatusCode::BAD_REQUEST,
            "analytics requires a nonnegative range of at most 30 days".into(),
        ));
    }
    // Counts include whole overlapping hours, including the latest persisted
    // partial hour. Minute and hourly history are never combined.
    let from = from / 3600 * 3600;
    let to = to / 3600 * 3600;
    let enrichment = app.ip_enrichment.clone();
    let builder = app
        .db
        .fold_hourly_history(
            from,
            to,
            crate::analytics::Builder::new(from, to),
            move |builder, bucket| {
                builder.add(bucket, |ip| enrichment.lookup(ip));
            },
        )
        .await?;
    Ok(Json(builder.finish()))
}
#[derive(Deserialize)]
struct SourceTrafficQuery {
    from: Option<i64>,
    to: Option<i64>,
    resolution: Option<String>,
    protocol: Option<u8>,
    port: Option<u16>,
    cursor: Option<String>,
    limit: Option<usize>,
}
async fn source_traffic(
    State(app): State<App>,
    Path(ip): Path<String>,
    Query(q): Query<SourceTrafficQuery>,
) -> Result<Json<TrafficPage>, ApiError> {
    let ip = ip
        .parse::<IpAddr>()
        .map_err(|_| ApiError(StatusCode::BAD_REQUEST, "invalid IP address".into()))?;
    if q.cursor.as_ref().is_some_and(|c| c.len() > 2048) {
        return Err(ApiError(StatusCode::BAD_REQUEST, "cursor too long".into()));
    }
    let cursor = q
        .cursor
        .map(|c| serde_json::from_str::<(String, String, u8, i32)>(&c))
        .transpose()
        .map_err(|_| ApiError(StatusCode::BAD_REQUEST, "invalid cursor".into()))?;
    let now = unix_now();
    let query = TrafficQuery {
        ip: Some(ip),
        destination: None,
        interface: None,
        source_port: None,
        resolution: q.resolution.unwrap_or("minute".into()),
        from: q.from.unwrap_or(now - 86400),
        to: q.to.unwrap_or(now),
        protocol: q.protocol,
        port: q.port,
        cursor: cursor.map(|c| (ip.to_string(), c.0, c.1, c.2, c.3)),
        limit: q.limit.unwrap_or(100),
    };
    if !(1..=500).contains(&query.limit) {
        return Err(ApiError(
            StatusCode::BAD_REQUEST,
            "limit must be between 1 and 500".into(),
        ));
    }
    let live = app.live_traffic.read().await.for_query(&query);
    let mut page = app.db.source_traffic(query, live).await?;
    page.ip_info = app.ip_enrichment.lookup(ip);
    // Preserve the source inspector's existing four-field cursor contract.
    if let Some(cursor) = &page.next_cursor {
        let c: TrafficCursor = serde_json::from_str(cursor).map_err(anyhow::Error::from)?;
        page.next_cursor =
            Some(serde_json::to_string(&(c.1, c.2, c.3, c.4)).map_err(anyhow::Error::from)?);
    }
    Ok(Json(page))
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct TrafficSearch {
    from: Option<i64>,
    to: Option<i64>,
    resolution: Option<String>,
    source: Option<IpAddr>,
    destination: Option<IpAddr>,
    interface: Option<String>,
    protocol: Option<u8>,
    port: Option<u16>,
    source_port: Option<u16>,
    country: Option<String>,
    asn: Option<u32>,
    organization: Option<String>,
    cursor: Option<String>,
    limit: Option<usize>,
}
impl TrafficSearch {
    fn matches_source(&self, info: Option<&IpInfo>) -> bool {
        self.country.as_ref().is_none_or(|country| {
            if country == "unknown" {
                info.and_then(|i| i.country_code.as_ref()).is_none()
            } else {
                info.and_then(|i| i.country_code.as_ref())
                    .is_some_and(|code| code.eq_ignore_ascii_case(country))
            }
        }) && self
            .asn
            .is_none_or(|asn| info.and_then(|i| i.asn) == Some(asn))
            && self.organization.as_ref().is_none_or(|name| {
                info.and_then(|i| i.organization.as_ref())
                    .is_some_and(|org| org.to_lowercase().contains(&name.to_lowercase()))
            })
    }
}
async fn traffic_query(
    State(app): State<App>,
    Query(search): Query<TrafficSearch>,
) -> Result<Json<serde_json::Value>, ApiError> {
    if search.country.as_ref().is_some_and(|c| {
        c != "unknown" && (c.len() != 2 || !c.bytes().all(|b| b.is_ascii_alphabetic()))
    }) {
        return Err(ApiError(
            StatusCode::BAD_REQUEST,
            "country must be a two-letter code or unknown".into(),
        ));
    }
    if search.organization.as_ref().is_some_and(|s| s.len() > 200)
        || search.interface.as_ref().is_some_and(|s| s.len() > 128)
        || search.cursor.as_ref().is_some_and(|s| s.len() > 2048)
    {
        return Err(ApiError(
            StatusCode::BAD_REQUEST,
            "filter or cursor too long".into(),
        ));
    }
    let now = unix_now();
    let query = TrafficQuery {
        ip: search.source,
        destination: search.destination,
        interface: search.interface.clone(),
        source_port: search.source_port,
        resolution: search.resolution.clone().unwrap_or("minute".into()),
        from: search.from.unwrap_or(now - 86400),
        to: search.to.unwrap_or(now),
        protocol: search.protocol,
        port: search.port,
        limit: search.limit.unwrap_or(100),
        cursor: search
            .cursor
            .as_ref()
            .map(|c| serde_json::from_str::<TrafficCursor>(c))
            .transpose()
            .map_err(|_| ApiError(StatusCode::BAD_REQUEST, "invalid cursor".into()))?,
    };
    if !(1..=500).contains(&query.limit)
        || !["minute", "hour"].contains(&query.resolution.as_str())
        || query.from < 0
        || query.to < query.from
        || query.to - query.from > 90 * 86400
    {
        return Err(ApiError(
            StatusCode::BAD_REQUEST,
            "invalid range, resolution, or limit; maximum 90 days and 500 groups".into(),
        ));
    }
    let enrichment = app.ip_enrichment.clone();
    let live = app
        .live_traffic
        .read()
        .await
        .for_query_matching(&query, |ip| {
            search.matches_source(enrichment.lookup(ip).as_ref())
        });
    let lookup = app.ip_enrichment.clone();
    let page = app
        .db
        .query_traffic(query, live, move |ip| {
            search.matches_source(lookup.lookup(ip).as_ref())
        })
        .await?;
    let sources: std::collections::BTreeMap<_, _> = page
        .rows
        .iter()
        .map(|row| (row.source.to_string(), enrichment.lookup(row.source)))
        .collect();
    let mut result = serde_json::to_value(page).map_err(anyhow::Error::from)?;
    result["sources"] = serde_json::to_value(sources).map_err(anyhow::Error::from)?;
    Ok(Json(result))
}

async fn events(
    State(app): State<App>,
    Query(q): Query<EventsQuery>,
) -> Result<Json<Vec<einblick_core::Event>>, ApiError> {
    if let Some(ip) = q.ip {
        return Ok(Json(
            app.db
                .events_for_source(ip, q.limit.unwrap_or(100), q.before.unwrap_or(i64::MAX))
                .await?,
        ));
    }
    Ok(Json(
        app.db
            .events(q.limit.unwrap_or(100), q.before.unwrap_or(i64::MAX))
            .await?,
    ))
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct NewRule {
    network: IpNet,
    kind: RuleKind,
    reason: String,
    seconds: Option<i64>,
}
async fn send(app: &App, action: Action) -> Result<Json<serde_json::Value>, ApiError> {
    let (tx, rx) = oneshot::channel();
    app.commands
        .try_send(Command { action, reply: tx })
        .map_err(|_| {
            ApiError(
                StatusCode::SERVICE_UNAVAILABLE,
                "control queue unavailable".into(),
            )
        })?;
    rx.await
        .map_err(|_| ApiError(StatusCode::SERVICE_UNAVAILABLE, "monitor stopped".into()))??;
    Ok(Json(
        serde_json::json!({"accepted":true,"message":"Check rule applied/error status for enforcement outcome."}),
    ))
}
async fn add_rule(
    State(app): State<App>,
    Json(r): Json<NewRule>,
) -> Result<Json<serde_json::Value>, ApiError> {
    send(
        &app,
        Action::Add {
            network: r.network,
            kind: r.kind,
            reason: r.reason,
            seconds: r.seconds,
        },
    )
    .await
}
async fn remove_rule(
    State(app): State<App>,
    Path(id): Path<i64>,
) -> Result<Json<serde_json::Value>, ApiError> {
    send(&app, Action::Remove(id)).await
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Mode {
    automatic: bool,
    blocking: bool,
    acknowledged: bool,
}
async fn mode(
    State(app): State<App>,
    Json(m): Json<Mode>,
) -> Result<Json<serde_json::Value>, ApiError> {
    send(
        &app,
        Action::Mode {
            automatic: m.automatic,
            blocking: m.blocking,
            acknowledged: m.acknowledged,
        },
    )
    .await
}
async fn emergency(State(app): State<App>) -> Result<Json<serde_json::Value>, ApiError> {
    send(&app, Action::Emergency).await
}
async fn health(State(app): State<App>) -> Response {
    let s = app.snapshot.read().await;
    let ok = s.health.storage_ok && s.health.enforcement_ok && unix_now() - s.health.last_tick < 5;
    (
        if ok {
            StatusCode::OK
        } else {
            StatusCode::SERVICE_UNAVAILABLE
        },
        Json(serde_json::json!({"ready":ok})),
    )
        .into_response()
}
async fn asset(request: Request<Body>) -> Response {
    if request.method() != Method::GET {
        return StatusCode::METHOD_NOT_ALLOWED.into_response();
    }
    let path = request.uri().path().trim_start_matches('/');
    // Development assets use a filesystem backend; never pass traversal or
    // encoded path components to it. Release assets have the same contract.
    if path.contains(['\\', '%']) || path.split('/').any(|p| p == ".." || p == ".") {
        return StatusCode::NOT_FOUND.into_response();
    }
    if path.starts_with("api/") {
        return StatusCode::NOT_FOUND.into_response();
    }
    let path = if path.is_empty() { "index.html" } else { path };
    match Assets::get(path) {
        Some(a) => (
            [(
                header::CONTENT_TYPE,
                mime_guess::from_path(path)
                    .first_or_octet_stream()
                    .to_string(),
            )],
            a.data.into_owned(),
        )
            .into_response(),
        None => StatusCode::NOT_FOUND.into_response(),
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    use http_body_util::BodyExt;
    use tower::ServiceExt;
    fn app() -> App {
        let config = Config {
            mock: true,
            secure_cookies: false,
            public_origin: "http://localhost:9080".into(),
            ..Config::default()
        };
        let (tx, _) = mpsc::channel(16);
        let (updates, _) = broadcast::channel(4);
        App {
            config: Arc::new(config),
            db: Database::open(":memory:").unwrap(),
            auth: Arc::new(Auth::new("test password long enough").unwrap()),
            snapshot: Arc::new(RwLock::new(Snapshot::default())),
            live_traffic: Arc::new(RwLock::new(LiveTraffic::default())),
            ip_enrichment: crate::ip_enrichment::Enrichment::default(),
            commands: tx,
            updates,
            shutdown: broadcast::channel(1).0,
        }
    }
    #[tokio::test]
    async fn analytics_auth_ranges_and_current_enrichment() {
        let mut app = app();
        app.ip_enrichment = crate::ip_enrichment::tests::fixture_enrichment();
        let at = unix_now() / 3600 * 3600;
        app.db
            .aggregate(
                Aggregate {
                    at,
                    totals: Totals {
                        packets: 100,
                        bytes: 1000,
                        passed: 95,
                        dropped: 5,
                        ..Default::default()
                    },
                    sources: vec![Source {
                        ip: "8.8.8.8".parse().unwrap(),
                        packets: 70,
                        bytes: 700,
                        syns: 1,
                        generation: 0,
                        ip_info: None,
                    }],
                    ports: vec![Port {
                        protocol: 6,
                        port: 443,
                        packets: 100,
                    }],
                    complete: true,
                },
                app.config.retention.clone(),
            )
            .await
            .unwrap();
        let (session, _) = app
            .auth
            .login(
                "127.0.0.1".parse().unwrap(),
                "test password long enough".into(),
            )
            .await
            .unwrap();
        let router = router(app);
        let response = router
            .clone()
            .oneshot(
                Request::builder()
                    .uri("/api/v1/analytics")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
        for path in [
            "/api/v1/analytics?from=-1",
            "/api/v1/analytics?from=10&to=9",
            "/api/v1/analytics?from=0&to=2678400",
            "/api/v1/analytics?resolution=minute",
        ] {
            let response = router
                .clone()
                .oneshot(
                    Request::builder()
                        .uri(path)
                        .header(header::COOKIE, format!("einblick_session={session}"))
                        .body(Body::empty())
                        .unwrap(),
                )
                .await
                .unwrap();
            assert_eq!(response.status(), StatusCode::BAD_REQUEST, "{path}");
        }
        let response = router
            .oneshot(
                Request::builder()
                    .uri(format!("/api/v1/analytics?from={at}&to={at}"))
                    .header(header::COOKIE, format!("einblick_session={session}"))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let body: serde_json::Value =
            serde_json::from_slice(&response.into_body().collect().await.unwrap().to_bytes())
                .unwrap();
        assert_eq!(body["totals"]["packets"], 100);
        assert_eq!(body["country_mapped"]["packets"], 70);
        let countries = body["countries"].as_array().unwrap();
        assert!(
            countries
                .iter()
                .any(|r| r["key"] == "RO" && r["packets"] == 70)
        );
        assert!(
            countries
                .iter()
                .any(|r| r["key"] == "untracked" && r["packets"] == 30)
        );
        assert_eq!(body["timeline"].as_array().unwrap().len(), 1);
    }
    #[tokio::test]
    async fn query_auth_enrichment_filters_validation_and_legacy_cursor() {
        let mut app = app();
        app.ip_enrichment = crate::ip_enrichment::tests::fixture_enrichment();
        let row = |source: &str, port| TrafficRecord {
            source: source.parse().unwrap(),
            destination: "192.0.2.1".parse().unwrap(),
            interface: "eth0".into(),
            protocol: 6,
            port: Some(port),
            counts: TrafficCounts {
                packets: 3,
                ..Default::default()
            },
            first_seen: 120,
            last_seen: 129,
            source_ports: vec![51000],
            source_ports_truncated: false,
            application_attribution: Default::default(),
        };
        app.db
            .detail_checkpoint(
                DetailBatch {
                    run: "query".into(),
                    sequence: 1,
                    from: 120,
                    to: 130,
                    rows: vec![
                        row("192.168.1.1", 443),
                        row("8.8.8.8", 443),
                        row("8.8.8.8", 22),
                    ],
                    complete: true,
                    omitted: 0,
                    gap_from: None,
                },
                app.config.retention.clone(),
                1000,
            )
            .await
            .unwrap();
        let (session, _) = app
            .auth
            .login(
                "127.0.0.1".parse().unwrap(),
                "test password long enough".into(),
            )
            .await
            .unwrap();
        let router = router(app);
        let response = router
            .clone()
            .oneshot(
                Request::builder()
                    .uri("/api/v1/traffic")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
        for query in [
            "country=China",
            "from=-1",
            "from=9&to=8",
            "from=0&to=7776001",
            "resolution=day",
            "limit=0",
            "source=bad",
            "source_port=65536",
            "cursor=bad",
            "unknown=x",
        ] {
            let response = router
                .clone()
                .oneshot(
                    Request::builder()
                        .uri(format!("/api/v1/traffic?{query}"))
                        .header(header::COOKIE, format!("einblick_session={session}"))
                        .body(Body::empty())
                        .unwrap(),
                )
                .await
                .unwrap();
            assert_eq!(response.status(), StatusCode::BAD_REQUEST, "{query}");
        }
        for (filters, expected) in [
            (
                "country=ro&asn=64512&organization=eXaMpLe&port=443&source_port=51000",
                1,
            ),
            ("country=CN", 0),
            ("country=unknown", 1),
            ("asn=999", 0),
            ("organization=nomatch", 0),
            ("destination=192.0.2.99", 0),
        ] {
            let response = router
                .clone()
                .oneshot(
                    Request::builder()
                        .uri(format!("/api/v1/traffic?from=120&to=130&{filters}"))
                        .header(header::COOKIE, format!("einblick_session={session}"))
                        .body(Body::empty())
                        .unwrap(),
                )
                .await
                .unwrap();
            assert_eq!(response.status(), StatusCode::OK);
            let body: serde_json::Value =
                serde_json::from_slice(&response.into_body().collect().await.unwrap().to_bytes())
                    .unwrap();
            assert_eq!(
                body["rows"].as_array().unwrap().len(),
                expected,
                "{filters}"
            );
            if filters.starts_with("country=ro") {
                assert_eq!(body["sources"]["8.8.8.8"]["asn"], 64512);
            }
        }
        let response = router
            .oneshot(
                Request::builder()
                    .uri("/api/v1/sources/8.8.8.8/traffic?from=120&to=130&limit=1")
                    .header(header::COOKIE, format!("einblick_session={session}"))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        let body: serde_json::Value =
            serde_json::from_slice(&response.into_body().collect().await.unwrap().to_bytes())
                .unwrap();
        let cursor: serde_json::Value =
            serde_json::from_str(body["next_cursor"].as_str().unwrap()).unwrap();
        assert_eq!(cursor.as_array().unwrap().len(), 4);
    }

    #[tokio::test]
    async fn source_inspector_enriches_untracked_ips_and_preserves_traffic() {
        let mut app = app();
        app.ip_enrichment = crate::ip_enrichment::tests::fixture_enrichment();
        let (session, _) = app
            .auth
            .login(
                "127.0.0.1".parse().unwrap(),
                "test password long enough".into(),
            )
            .await
            .unwrap();
        let router = router(app);
        for ip in ["8.8.8.8", "2001:4860:4860::8888", "192.168.1.1"] {
            let response = router
                .clone()
                .oneshot(
                    Request::builder()
                        .uri(format!("/api/v1/sources/{ip}/traffic"))
                        .header(header::COOKIE, format!("einblick_session={session}"))
                        .body(Body::empty())
                        .unwrap(),
                )
                .await
                .unwrap();
            assert_eq!(response.status(), StatusCode::OK);
            let body: serde_json::Value =
                serde_json::from_slice(&response.into_body().collect().await.unwrap().to_bytes())
                    .unwrap();
            assert!(body["rows"].as_array().unwrap().is_empty());
            if ip == "192.168.1.1" {
                assert!(body["ip_info"].is_null());
            } else {
                assert_eq!(body["ip_info"]["country_code"], "RO");
                assert_eq!(body["ip_info"]["asn"], 64512);
            }
        }
    }

    #[tokio::test]
    async fn auth_origin_csrf_and_logout() {
        let app = app();
        let router = router(app);
        assert_eq!(
            router
                .clone()
                .oneshot(
                    Request::builder()
                        .uri("/../../Cargo.toml")
                        .body(Body::empty())
                        .unwrap()
                )
                .await
                .unwrap()
                .status(),
            StatusCode::NOT_FOUND
        );
        assert_eq!(
            router
                .clone()
                .oneshot(
                    Request::builder()
                        .uri("/api/v1/snapshot")
                        .body(Body::empty())
                        .unwrap()
                )
                .await
                .unwrap()
                .status(),
            StatusCode::UNAUTHORIZED
        );
        let login = |origin: &str| {
            Request::builder()
                .method("POST")
                .uri("/api/v1/auth/login")
                .header("origin", origin)
                .header("content-type", "application/json")
                .body(Body::from(r#"{"password":"test password long enough"}"#))
                .unwrap()
        };
        assert_eq!(
            router
                .clone()
                .oneshot(login("http://evil.test"))
                .await
                .unwrap()
                .status(),
            StatusCode::FORBIDDEN
        );
        let res = router
            .clone()
            .oneshot(login("http://localhost:9080"))
            .await
            .unwrap();
        assert_eq!(res.status(), StatusCode::OK);
        let cookie = res.headers()[header::SET_COOKIE]
            .to_str()
            .unwrap()
            .split(';')
            .next()
            .unwrap()
            .to_owned();
        let value: serde_json::Value =
            serde_json::from_slice(&res.into_body().collect().await.unwrap().to_bytes()).unwrap();
        let csrf = value["csrf"].as_str().unwrap();
        let req = || {
            Request::builder()
                .method("POST")
                .uri("/api/v1/auth/logout")
                .header("cookie", &cookie)
                .header("origin", "http://localhost:9080")
        };
        assert_eq!(
            router
                .clone()
                .oneshot(req().body(Body::empty()).unwrap())
                .await
                .unwrap()
                .status(),
            StatusCode::FORBIDDEN
        );
        assert_eq!(
            router
                .clone()
                .oneshot(
                    req()
                        .header("x-csrf-token", csrf)
                        .body(Body::empty())
                        .unwrap()
                )
                .await
                .unwrap()
                .status(),
            StatusCode::NO_CONTENT
        );
        assert_eq!(
            router
                .oneshot(
                    Request::builder()
                        .uri("/api/v1/snapshot")
                        .header("cookie", cookie)
                        .body(Body::empty())
                        .unwrap()
                )
                .await
                .unwrap()
                .status(),
            StatusCode::UNAUTHORIZED
        );
    }
}
