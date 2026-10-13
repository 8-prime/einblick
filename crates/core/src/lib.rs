pub mod config;
pub mod detector;
pub mod model;
pub mod storage;
pub mod traffic;
mod traffic_storage;
pub use application::*;
pub use config::Config;
pub use model::*;
pub use traffic::*;

pub fn unix_now() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as i64
}
pub mod application;
