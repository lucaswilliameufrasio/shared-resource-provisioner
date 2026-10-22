ALTER TABLE resources
    ADD COLUMN credential_generation INTEGER NOT NULL DEFAULT 1 CHECK(credential_generation > 0);

ALTER TABLE resources
    ADD COLUMN rotation_status TEXT NOT NULL DEFAULT ''
        CHECK(rotation_status IN ('', 'staging', 'pending', 'finalizing', 'reconciliation_required'));

CREATE TABLE resource_rotations (
    operation_id TEXT PRIMARY KEY REFERENCES operations(id) ON DELETE RESTRICT,
    resource_id TEXT NOT NULL REFERENCES resources(id) ON DELETE RESTRICT,
    old_generation INTEGER NOT NULL CHECK(old_generation > 0),
    new_generation INTEGER NOT NULL CHECK(new_generation > old_generation),
    old_secret_uri TEXT NOT NULL,
    old_secret_version TEXT NOT NULL DEFAULT '',
    credential_name TEXT NOT NULL,
    secret_uri TEXT NOT NULL,
    secret_version TEXT NOT NULL DEFAULT '',
    status TEXT NOT NULL CHECK(status IN ('staging', 'pending', 'finalizing', 'reconciliation_required', 'completed', 'failed')),
    acknowledged_at_ns INTEGER NOT NULL DEFAULT 0,
    lease_expires_ns INTEGER NOT NULL DEFAULT 0,
    created_at_ns INTEGER NOT NULL,
    updated_at_ns INTEGER NOT NULL,
    UNIQUE(resource_id, new_generation)
);

CREATE INDEX resource_rotations_resource_idx
    ON resource_rotations(resource_id, new_generation);
