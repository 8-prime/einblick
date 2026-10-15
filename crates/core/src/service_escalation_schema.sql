CREATE TABLE service_ban_history (
    service_id INTEGER NOT NULL,
    policy_id TEXT NOT NULL,
    source_ip TEXT NOT NULL,
    last_ban INTEGER NOT NULL,
    ban_count INTEGER NOT NULL,
    reset_at INTEGER NOT NULL,
    PRIMARY KEY(service_id, policy_id, source_ip)
);
CREATE INDEX service_ban_history_reset ON service_ban_history(reset_at);
PRAGMA user_version=5;
