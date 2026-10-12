CREATE TABLE traffic (
 resolution TEXT NOT NULL, at INTEGER NOT NULL, source TEXT NOT NULL,
 destination TEXT NOT NULL, interface TEXT NOT NULL, protocol INTEGER NOT NULL,
 port INTEGER NOT NULL, packets INTEGER NOT NULL, bytes INTEGER NOT NULL,
 passed INTEGER NOT NULL, dropped INTEGER NOT NULL, syns INTEGER NOT NULL,
 syn_acks INTEGER NOT NULL, resets INTEGER NOT NULL, first_seen INTEGER NOT NULL,
 last_seen INTEGER NOT NULL, source_ports TEXT NOT NULL, truncated INTEGER NOT NULL,
 PRIMARY KEY(resolution,at,source,destination,interface,protocol,port)
);
CREATE INDEX traffic_source ON traffic(source,resolution,at);
CREATE TABLE traffic_coverage (
 resolution TEXT NOT NULL, at INTEGER NOT NULL, complete INTEGER NOT NULL,
 omitted INTEGER NOT NULL, first_seen INTEGER NOT NULL, last_seen INTEGER NOT NULL,
 PRIMARY KEY(resolution,at)
);
CREATE TABLE traffic_batches (run TEXT NOT NULL, sequence INTEGER NOT NULL,
 at INTEGER NOT NULL, PRIMARY KEY(run,sequence));
PRAGMA user_version=2;
