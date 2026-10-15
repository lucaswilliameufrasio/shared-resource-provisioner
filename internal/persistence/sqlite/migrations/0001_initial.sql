CREATE TABLE grants (
    id TEXT PRIMARY KEY,
    subject TEXT NOT NULL,
    application TEXT NOT NULL,
    environment TEXT NOT NULL,
    action TEXT NOT NULL,
    created_at_ns INTEGER NOT NULL,
    created_by TEXT NOT NULL,
    UNIQUE(subject, application, environment, action)
);

CREATE INDEX grants_page_idx ON grants(created_at_ns, id);

CREATE TABLE audit_events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    event_at_ns INTEGER NOT NULL,
    actor_subject TEXT NOT NULL,
    target_subject TEXT NOT NULL DEFAULT '',
    transport TEXT NOT NULL DEFAULT '',
    action TEXT NOT NULL,
    entity_id TEXT NOT NULL DEFAULT '',
    application TEXT NOT NULL DEFAULT '',
    environment TEXT NOT NULL DEFAULT '',
    resource_type TEXT NOT NULL DEFAULT '',
    outcome TEXT NOT NULL,
    error_code TEXT NOT NULL DEFAULT ''
);

CREATE INDEX audit_events_time_idx ON audit_events(event_at_ns, id);

CREATE TRIGGER audit_events_no_update
BEFORE UPDATE ON audit_events
BEGIN
    SELECT RAISE(ABORT, 'audit events are append-only');
END;

CREATE TRIGGER audit_events_no_delete
BEFORE DELETE ON audit_events
BEGIN
    SELECT RAISE(ABORT, 'audit events are append-only');
END;

CREATE TABLE resources (
    id TEXT PRIMARY KEY,
    resource_type TEXT NOT NULL CHECK(resource_type IN ('postgresql', 'valkey', 'nats')),
    application TEXT NOT NULL,
    environment TEXT NOT NULL,
    logical_name TEXT NOT NULL,
    target_id TEXT NOT NULL,
    status TEXT NOT NULL CHECK(status IN ('provisioning', 'active', 'failed', 'reconciliation_required', 'revocation_pending', 'revoked')),
    secret_uri TEXT NOT NULL DEFAULT '',
    secret_version TEXT NOT NULL DEFAULT '',
    error_code TEXT NOT NULL DEFAULT '',
    created_at_ns INTEGER NOT NULL,
    updated_at_ns INTEGER NOT NULL,
    UNIQUE(resource_type, application, environment)
);

CREATE TABLE operations (
    id TEXT PRIMARY KEY,
    idempotency_key TEXT NOT NULL,
    subject TEXT NOT NULL,
    action TEXT NOT NULL,
    request_hash TEXT NOT NULL,
    status TEXT NOT NULL CHECK(status IN ('accepted', 'running', 'succeeded', 'failed', 'reconciliation_required')),
    resource_id TEXT NOT NULL REFERENCES resources(id) ON DELETE RESTRICT,
    error_code TEXT NOT NULL DEFAULT '',
    lease_expires_ns INTEGER NOT NULL DEFAULT 0,
    created_at_ns INTEGER NOT NULL,
    updated_at_ns INTEGER NOT NULL,
    UNIQUE(subject, idempotency_key)
);

CREATE TABLE control_metadata (
    key TEXT PRIMARY KEY,
    value TEXT NOT NULL
);
