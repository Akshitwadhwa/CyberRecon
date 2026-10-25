-- CyberRecon evidence store. Gold labels are NOT stored here so agents cannot cheat.

CREATE TABLE IF NOT EXISTS incidents (
    id TEXT PRIMARY KEY,
    title TEXT NOT NULL,
    t_start TEXT NOT NULL,
    t_end TEXT NOT NULL,
    ticket_text TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS events (
    id TEXT PRIMARY KEY,
    incident_id TEXT NOT NULL,
    timestamp TEXT NOT NULL,
    source TEXT NOT NULL CHECK (source IN ('network', 'endpoint', 'identity', 'alert_image')),
    event_type TEXT NOT NULL,
    payload TEXT NOT NULL,
    FOREIGN KEY (incident_id) REFERENCES incidents (id)
);

CREATE TABLE IF NOT EXISTS intel (
    indicator TEXT PRIMARY KEY,
    indicator_type TEXT NOT NULL,
    confidence TEXT NOT NULL,
    note TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_events_incident_source
    ON events (incident_id, source, timestamp);
