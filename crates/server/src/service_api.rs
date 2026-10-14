use crate::{
    api::{ApiError, App},
    service_logs,
};
use anyhow::ensure;
use axum::{
    Json, Router,
    extract::{DefaultBodyLimit, Path, State},
    routing::{get, post},
};
use einblick_core::{services::*, unix_now};
use serde::Deserialize;
static EVALUATIONS: tokio::sync::Semaphore = tokio::sync::Semaphore::const_new(2);

pub fn routes() -> Router<App> {
    Router::new()
        .route("/services", get(list).post(create))
        .route("/services/templates", get(templates))
        .route("/services/playground", post(simulate))
        .route("/services/preview", post(preview))
        .route("/services/{id}", get(detail).put(save).delete(delete))
        .route("/services/{id}/history-simulation", post(historical))
        .route("/services/{id}/sources/{source}/reset", post(reset_source))
        .layer(DefaultBodyLimit::max(192 * 1024))
}
async fn list(State(app): State<App>) -> Result<Json<Vec<ProtectedService>>, ApiError> {
    Ok(Json(app.db.services().await?))
}
async fn reset_source(
    State(app): State<App>,
    Path((id, source)): Path<(i64, String)>,
) -> Result<axum::http::StatusCode, ApiError> {
    app.db.reset_service_source(id, source, unix_now()).await?;
    Ok(axum::http::StatusCode::NO_CONTENT)
}
async fn templates() -> Json<serde_json::Value> {
    Json(
        serde_json::json!([{"id":"openssh","name":"OpenSSH brute-force protection","service":ssh_template()}]),
    )
}
fn validate_paths(app: &App, service: &ProtectedService) -> anyhow::Result<()> {
    service.validate()?;
    for source in &service.sources {
        if let SourceInput::File { path } = &source.input {
            let p = std::path::Path::new(path);
            ensure!(
                !p.components().any(|c| matches!(
                    c,
                    std::path::Component::ParentDir | std::path::Component::CurDir
                )),
                "log path must not contain traversal"
            );
            ensure!(
                app.config
                    .service_logs
                    .allowed_roots
                    .iter()
                    .any(|r| p.starts_with(r) && p != std::path::Path::new(r)),
                "log path is outside configured service_logs.allowed_roots"
            );
            // Inaccessible sources may be saved for deployment, but existing files must be safe.
            if p.exists() {
                service_logs::open_log(&app.config.service_logs, path)?;
            }
        }
    }
    Ok(())
}
async fn create(
    State(app): State<App>,
    Json(service): Json<ProtectedService>,
) -> Result<Json<ProtectedService>, ApiError> {
    validate_paths(&app, &service)?;
    Ok(Json(app.db.save_service(service, true, unix_now()).await?))
}
async fn save(
    State(app): State<App>,
    Path(id): Path<i64>,
    Json(mut service): Json<ProtectedService>,
) -> Result<Json<ProtectedService>, ApiError> {
    service.id = id;
    validate_paths(&app, &service)?;
    Ok(Json(app.db.save_service(service, false, unix_now()).await?))
}
async fn delete(
    State(app): State<App>,
    Path(id): Path<i64>,
) -> Result<axum::http::StatusCode, ApiError> {
    app.db.delete_service(id, unix_now()).await?;
    Ok(axum::http::StatusCode::NO_CONTENT)
}
async fn detail(
    State(app): State<App>,
    Path(id): Path<i64>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let service = app.db.service(id).await?;
    let mut sources = app.db.source_states(id).await?;
    for state in sources.values_mut() {
        if matches!(state.status.as_str(), "healthy" | "warming")
            && (state.updated < unix_now() - 10 || state.updated > unix_now() + 5)
        {
            state.status = "stale".into();
            state.error = Some(
                "Collector has not reported recently; inspect source access and server logs".into(),
            );
        }
    }
    let active_sources: Vec<_> = service.sources.iter().filter(|s| s.enabled).collect();
    let complete = !active_sources.is_empty()
        && active_sources.iter().all(|s| {
            sources.get(&s.id).is_some_and(|state| {
                state.revision == service.revision && state.status == "healthy"
            })
        });
    let policy_health: std::collections::BTreeMap<_, _> = service
        .policies
        .iter()
        .map(|p| {
            (
                p.id.clone(),
                if !service.enabled || !p.enabled {
                    "disabled"
                } else if active_sources.is_empty() {
                    "no_active_sources"
                } else if !complete {
                    "warming_or_incomplete"
                } else {
                    "ready"
                },
            )
        })
        .collect();
    let events = app.db.security_events(id, 200).await?;
    let decisions = app.db.service_decisions(id).await?;
    Ok(Json(
        serde_json::json!({"service":service,"source_health":sources,"policy_health":policy_health,"events":events,"decisions":decisions,"access":{"allowed_roots":app.config.service_logs.allowed_roots,"journal_directory":app.config.service_logs.journal_directory}}),
    ))
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Playground {
    service: ProtectedService,
    source_id: String,
    input: String,
    #[serde(default = "spacing")]
    spacing_seconds: i64,
}
fn spacing() -> i64 {
    1
}
async fn simulate(Json(input): Json<Playground>) -> Result<Json<Simulation>, ApiError> {
    let permit = EVALUATIONS.try_acquire().map_err(|_| {
        ApiError(
            axum::http::StatusCode::TOO_MANY_REQUESTS,
            "playground busy; retry shortly".into(),
        )
    })?;
    // Use real Rust regex and policy code. CPU-bound work stays off the async runtime.
    Ok(Json(
        tokio::task::spawn_blocking(move || {
            let _permit = permit;
            playground(
                &input.service,
                &input.source_id,
                &input.input,
                unix_now(),
                input.spacing_seconds,
            )
        })
        .await
        .map_err(anyhow::Error::from)??,
    ))
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Preview {
    source: LogSource,
}
async fn preview(
    State(app): State<App>,
    Json(input): Json<Preview>,
) -> Result<Json<serde_json::Value>, ApiError> {
    // Raw log sampling remains usable while the filter editor has invalid regexes.
    input.source.input.validate()?;
    service_logs::validate_source(&app.config.service_logs, &input.source)?;
    let lines = service_logs::preview(app.config.service_logs.clone(), input.source).await?;
    Ok(Json(
        serde_json::json!({"lines":lines,"timing":"Preview text; journal timestamps are not included. Use retained-event replay for historical timing."}),
    ))
}
async fn historical(
    State(app): State<App>,
    Path(id): Path<i64>,
    Json(mut service): Json<ProtectedService>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let permit = EVALUATIONS.try_acquire().map_err(|_| {
        ApiError(
            axum::http::StatusCode::TOO_MANY_REQUESTS,
            "simulation busy; retry shortly".into(),
        )
    })?;
    app.db.service(id).await?;
    service.id = id;
    service.validate()?;
    let stored = app.db.security_events(id, 10000).await?;
    let limited = app.db.security_event_count(id).await? > stored.len();
    let from = stored.last().map(|e| e.event.at);
    let to = stored.first().map(|e| e.event.at);
    let simulation = tokio::task::spawn_blocking(move || {
        let _permit = permit;
        simulate_events(&service, stored.into_iter().map(|e| e.event).collect())
    })
    .await
    .map_err(anyhow::Error::from)??;
    Ok(Json(
        serde_json::json!({"simulation":simulation,"limited":limited,"from":from,"to":to,"caveat":"Latest 10,000 retained normalized events / 4 MiB, evaluated against current policy settings. Filters are not reapplied to old raw logs. Excludes unobserved, ignored, and dropped logs; source gaps and prior enforcement can make evidence incomplete. Global allowlists and actual reachability are not simulated."}),
    ))
}
