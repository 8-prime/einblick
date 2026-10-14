CREATE TABLE protected_services(id INTEGER PRIMARY KEY AUTOINCREMENT, revision INTEGER NOT NULL, data TEXT NOT NULL, deleted INTEGER NOT NULL DEFAULT 0);
CREATE TABLE service_sources(service_id INTEGER NOT NULL, source_id TEXT NOT NULL, input TEXT NOT NULL, data TEXT NOT NULL, PRIMARY KEY(service_id,source_id));
CREATE TABLE security_events(id INTEGER PRIMARY KEY AUTOINCREMENT, service_id INTEGER NOT NULL, at INTEGER NOT NULL, event_key TEXT NOT NULL, data TEXT NOT NULL, UNIQUE(service_id,event_key));
CREATE INDEX security_events_service_at ON security_events(service_id,at,id);
CREATE INDEX security_events_at ON security_events(at);
CREATE TABLE service_decisions(id INTEGER PRIMARY KEY AUTOINCREMENT, service_id INTEGER NOT NULL, at INTEGER NOT NULL, data TEXT NOT NULL, status TEXT NOT NULL, rule_id INTEGER REFERENCES rules(id));
CREATE INDEX service_decisions_service_at ON service_decisions(service_id,at,id);
CREATE INDEX service_decisions_at ON service_decisions(at);
PRAGMA user_version=4;
