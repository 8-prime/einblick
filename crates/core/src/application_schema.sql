CREATE INDEX traffic_application_lookup ON traffic(source,resolution,destination,interface,protocol,port,at);
CREATE TABLE traffic_applications (
 resolution TEXT NOT NULL, at INTEGER NOT NULL, source TEXT NOT NULL,
 destination TEXT NOT NULL, interface TEXT NOT NULL, protocol INTEGER NOT NULL,
 port INTEGER NOT NULL, data TEXT NOT NULL CHECK(length(CAST(data AS BLOB))<=8192),
 PRIMARY KEY(resolution,at,source,destination,interface,protocol,port),
 FOREIGN KEY(resolution,at,source,destination,interface,protocol,port)
 REFERENCES traffic(resolution,at,source,destination,interface,protocol,port)
 ON DELETE CASCADE
);
PRAGMA user_version=3;
