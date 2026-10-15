CREATE TABLE caddy_requests (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    log_path TEXT NOT NULL,
    identity TEXT NOT NULL,
    at INTEGER NOT NULL,
    remote_ip TEXT NOT NULL,
    client_ip TEXT,
    host TEXT NOT NULL,
    path TEXT NOT NULL,
    method TEXT NOT NULL,
    status INTEGER NOT NULL,
    UNIQUE(log_path, identity)
);
CREATE INDEX caddy_requests_source ON caddy_requests(remote_ip, at DESC, id DESC);
CREATE INDEX caddy_requests_at ON caddy_requests(at, id);
CREATE TABLE caddy_sources (
    log_path TEXT PRIMARY KEY,
    cursor TEXT NOT NULL,
    last_poll INTEGER NOT NULL,
    last_success INTEGER,
    skipped INTEGER NOT NULL,
    gaps INTEGER NOT NULL,
    error TEXT
);
PRAGMA user_version=6;
