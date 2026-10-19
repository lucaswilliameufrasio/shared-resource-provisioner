# Control-plane host-loss recovery drill

This procedure restores the provisioner's SQLite control-plane state to a
separate recovery host. It is a runbook, not evidence that a production drill
has passed. Use only an isolated recovery environment until all checks are
complete.

## Before production

The operator must record and approve the following for the intended deployment:

- Backup frequency, encrypted off-host destination, retention, and access policy.
- Recovery point objective (RPO), recovery time objective (RTO), and the owner
  responsible for each drill.
- The exact application release and compatible recovery-host runtime.
- Independent recovery procedures for TLS/OIDC configuration, target endpoint
  files, PostgreSQL/Valkey/NATS administrative identities, and Ciphera service
  identities/projects. These are not contained in SQLite backups.
- A recovery host with no route to production targets during the initial
  read-only verification.

Do not invent an RPO/RTO or use the production target configuration as a test
fixture. Production mutations must remain disabled during the drill.

## Create and protect a backup

Run this on the control-plane host, substituting the operator-managed paths:

```sh
SRP_SQLITE_PATH=/var/lib/shared-resource-provisioner/control.db \
  ./bin/provisioner backup "/var/backups/shared-resource-provisioner/control-$(date -u +%Y%m%dT%H%M%SZ).db"
```

The destination directory must be accessible only to the service/operator
account. The command creates a SQLite-consistent snapshot, fails if the
destination already exists, and writes a `0600` file. Verify the file owner and
permissions, then transfer it with the approved encrypted off-host backup
system. Do not store the only copy on the control-plane host.

## Restore to an isolated recovery host

1. Select a backup using the off-host backup system's trusted integrity and
   provenance checks. Record its timestamp and checksum through the approved
   channel; do not place credential values in the drill record.
2. Create a new, owner-only database directory on the recovery host. Do not
   overwrite an existing control-plane database.
3. Restore the selected snapshot as the configured SQLite path. Preserve the
   service account as owner and set the file to `0600`; the parent directory
   must be `0700`.
4. If `sqlite3` is available on the recovery host, verify the copied file
   read-only with `PRAGMA integrity_check;` and require the result `ok`.
5. Start the matching provisioner release with mutations explicitly disabled.
   Do not provide production target endpoints to the recovery host. Keep TLS,
   OIDC, and administrator configuration protected and use the isolated
   recovery identity for verification.
6. Verify `/healthz`, authenticate to the grant administration API, and confirm
   expected grant records. Use known test resource IDs to inspect restored
   resource metadata and verify idempotency state using the approved read-only
   database inspection process. Confirm only secret references—not credential
   values—are present in provisioner responses and audit records.
7. Confirm mutation tools are not advertised while the mutation gate is off.
   Do not create, rotate, or revoke resources as part of this database-only
   recovery check.
8. Record the release, backup timestamp, checksum, measured recovery duration,
   verification results, and any gaps. Keep the recovery copy isolated until
   the drill owner approves cleanup.

## Acceptance criteria

- The backup can be transferred to a distinct recovery path and opened by the
  provisioner without broadening file permissions.
- Grant, resource, operation/idempotency, and audit state match the expected
  recovery point.
- The service starts in planning/read-only mode without connecting to shared or
  production resource targets.
- The recorded recovery duration and data-loss window meet the operator-approved
  RTO/RPO. If those values have not been approved, the drill is not complete.
- Target and Ciphera recovery have separate evidence. A healthy SQLite restore
  does not prove those external systems or credentials are available.

## After the drill

Do not enable mutations until the operator has separately verified target
limits, target credentials, Ciphera project/identity mappings, TLS/OIDC
configuration, monitoring, and compensation/reconciliation behavior. Keep the
last known-good backup unchanged until recovery approval.
