mod api;
mod auth;
mod backend;
mod monitor;
use anyhow::{Context, Result};
use einblick_core::{Config, Snapshot, storage::Database};
use std::{path::Path, sync::Arc};
use tokio::sync::{RwLock, broadcast, mpsc};

#[tokio::main(flavor = "multi_thread", worker_threads = 2)]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "einblick=info".into()),
        )
        .init();
    let args = std::env::args().skip(1).collect::<Vec<_>>();
    if args.first().is_some_and(|s| s == "--healthcheck") {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let bind = std::env::var("EINBLICK_HEALTH_ADDRESS").unwrap_or("127.0.0.1:9080".into());
        return tokio::time::timeout(std::time::Duration::from_secs(3), async {
            let mut stream = tokio::net::TcpStream::connect(bind).await?;
            stream
                .write_all(b"GET /healthz HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n")
                .await?;
            let mut b = [0; 128];
            let n = stream.read(&mut b).await?;
            anyhow::ensure!(b[..n].starts_with(b"HTTP/1.1 200"), "server unhealthy");
            Ok::<_, anyhow::Error>(())
        })
        .await?;
    }
    let path = if args.first().is_some_and(|s| s == "--config") {
        args.get(1).context("--config requires a path")?.as_str()
    } else {
        "einblick.toml"
    };
    let config = Config::load(Path::new(path))?;
    let password = std::fs::read_to_string(&config.password_file)
        .context("read mounted administrator password secret")?;
    let auth = Arc::new(auth::Auth::new(password.trim_end())?);
    drop(password);
    let db = Database::open(&config.database)?;
    let snapshot = Arc::new(RwLock::new(Snapshot::default()));
    let (commands, rx) = mpsc::channel(16);
    let (updates, _) = broadcast::channel(4);
    let (stop, _) = broadcast::channel(1);
    let monitor = monitor::Monitor::new(
        config.clone(),
        db.clone(),
        snapshot.clone(),
        updates.clone(),
    )
    .await?;
    let listener = tokio::net::TcpListener::bind(config.bind)
        .await
        .context("bind HTTP listener")?;
    let app = api::App {
        config: Arc::new(config.clone()),
        db,
        auth,
        snapshot,
        live_traffic: monitor.live_traffic.clone(),
        commands,
        updates,
        shutdown: stop.clone(),
    };
    use std::future::IntoFuture;
    let mut worker = tokio::spawn(monitor.run(rx, stop.subscribe()));
    tracing::info!(bind=%config.bind,mock=config.mock,"Einblick started");
    let mut shutdown = stop.subscribe();
    let server = axum::serve(
        listener,
        api::router(app).into_make_service_with_connect_info::<std::net::SocketAddr>(),
    )
    .with_graceful_shutdown(async move {
        let _ = shutdown.recv().await;
    })
    .into_future();
    tokio::pin!(server);
    let mut term = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
        .context("install SIGTERM handler")?;
    tokio::select! {
        _=async {tokio::select!{_=tokio::signal::ctrl_c()=>{},_=term.recv()=>{}}} => {
            let _=stop.send(());
            tokio::time::timeout(std::time::Duration::from_secs(8),async {server.await?;worker.await?;Ok::<_,anyhow::Error>(())}).await.context("shutdown exceeded eight seconds")??;
        },
        result=&mut worker=>{
            let _=stop.send(());
            let _=tokio::time::timeout(std::time::Duration::from_secs(5),server).await;
            result.context("monitor task failed")?;
            anyhow::bail!("monitor stopped unexpectedly");
        },
        result=&mut server=>{let _=stop.send(());worker.await?;result?;},
    }
    Ok(())
}
