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
        .route("/sources/{ip}/traffic", get(source_traffic))
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
        .map(|c| serde_json::from_str::<TrafficCursor>(&c))
        .transpose()
        .map_err(|_| ApiError(StatusCode::BAD_REQUEST, "invalid cursor".into()))?;
    let now = unix_now();
    let query = TrafficQuery {
        ip,
        resolution: q.resolution.unwrap_or("minute".into()),
        from: q.from.unwrap_or(now - 86400),
        to: q.to.unwrap_or(now),
        protocol: q.protocol,
        port: q.port,
        cursor,
        limit: q.limit.unwrap_or(100),
    };
    if !(1..=500).contains(&query.limit) {
        return Err(ApiError(
            StatusCode::BAD_REQUEST,
            "limit must be between 1 and 500".into(),
        ));
    }
    let live = app.live_traffic.read().await.for_query(&query);
    Ok(Json(app.db.source_traffic(query, live).await?))
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
            commands: tx,
            updates,
            shutdown: broadcast::channel(1).0,
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
