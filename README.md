# Shared Resource Provisioner

Independent Go control plane for provisioning shared PostgreSQL, Valkey, and
NATS resources with per-application and per-environment isolation. The project
does not depend on Uirapuru and is not a SQL query tool.

The control plane includes SQLite persistence, grant administration, audit,
Ciphera secret storage, PostgreSQL/Valkey/NATS drivers, and typed MCP lifecycle
actions. Mutations are disabled by default; without explicit operator
configuration, MCP exposes planning only. Credential values never cross MCP.
HTTP exposes staged rotation only when mutations are enabled. The workload gets
the pending reference through a separate OIDC-protected polling endpoint and
confirms the exact operation, reference, version, and generation before the old
target identity is retired. Rotation is not exposed over stdio.

## Security boundary

- MCP responses expose resource metadata and opaque secret references only;
  credential values never cross the MCP boundary.
- HTTP MCP uses Streamable HTTP and OIDC bearer-token authentication. stdio
  derives its principal from local process configuration. Both transports use
  the same deny-by-default authorization policy.
- Service endpoints and administrative credentials are server-side
  configuration, never MCP arguments.
- Ciphera is the selected secret store; Docker Compose workloads will consume
  references through `ciphera run` with a read-only scoped identity. This
  delivers plaintext to trusted processes and does not protect it from the host,
  Docker daemon, or workload code.
- Grant administration uses a REST API outside MCP, backed by SQLite and
  protected by an exact OIDC-subject allowlist in operator config.

See [architecture](docs/architecture.md), [decisions](docs/adr/), and the
[development plan](docs/roadmap.md) before extending the control plane.

## Development

Requires Go 1.27.3 or newer; it includes the standard-library fix for
GO-2026-6809, which `govulncheck` reports as reachable on Go 1.27.2. Unit tests
do not require Docker or external services. The opt-in integration suite uses
an isolated, loopback-only Compose project for PostgreSQL and Valkey and an
in-process NATS server. See
[TESTING_STANDARD.md](TESTING_STANDARD.md) for the exact checks.

Run the real-service driver integration suite from the repository root with
`./scripts/test-integration.sh`. It uses a unique Compose project and cleans up
only the containers and network it creates.

### Run the planning MCP locally

Create an authorization policy based on `config/policy.example.json`, replacing
the example subject with the exact local principal or OIDC `sub`. Then set:

```sh
export SRP_AUTHZ_POLICY_FILE=/secure/path/policy.json
export SRP_STDIO_SUBJECT=local-agent
go run ./cmd/provisioner stdio
```

For HTTP, configure `SRP_OIDC_ISSUER_URL`, `SRP_OIDC_AUDIENCE`,
`SRP_MCP_RESOURCE_URL` (the canonical public MCP URL, such as
`https://provisioner.example.test/mcp`), and optionally `SRP_HTTP_ADDR`
(defaults to `127.0.0.1:8080`). Non-loopback listeners also require
`SRP_TLS_CERT_FILE` and `SRP_TLS_KEY_FILE`. The health probe is `GET /healthz`;
the authenticated Streamable HTTP MCP endpoint is mounted at the path from
`SRP_MCP_RESOURCE_URL`. OAuth Protected Resource Metadata is served at the
corresponding `/.well-known/oauth-protected-resource/...` path and points to
the configured OIDC issuer. `SRP_OIDC_AUDIENCE` must match the audience claim
issued for this resource. The initial verifier supports signed JWT bearer
tokens; opaque-token introspection is not implemented yet.

The mutation gate defaults to off. Over HTTP, enabling it exposes typed
create/inspect/revoke/rotate tools plus the OIDC-protected workload rotation
polling and acknowledgement routes. The rotation tool is deliberately omitted
from stdio because stdio does not authenticate the workload's OIDC identity.
Operators must explicitly set `SRP_MUTATIONS_ENABLED=true` and configure both
`SRP_TARGETS_FILE` and `SRP_CIPHERA_CONFIG_FILE`. Example files contain only
secret-file paths and non-secret project identifiers:

- [Target configuration](config/targets.example.json)
- [Ciphera configuration](config/ciphera.example.json)

Endpoint URLs, PostgreSQL/Valkey administrative credentials, the NATS operator
seed, NATS system credentials, and the Ciphera service key belong in separate
owner-only files referenced by those configs. Review [the architecture and
operating constraints](docs/architecture.md) before enabling mutations. The
gate is not a substitute for protected SQLite backups, tested recovery, and
operator review of the target's isolation and limits.

The SQLite database must live in a service-owned directory with mode `0700` and
the database file must be `0600`; startup rejects broader permissions. See the
[deployment hardening checklist](docs/runbooks/deployment-hardening.md) for
network, identity, shutdown, logging, and operational requirements.

### Back up the control-plane database

Run the offline-capable backup subcommand against the configured SQLite file:

```sh
SRP_SQLITE_PATH=/var/lib/shared-resource-provisioner/control.db \
  ./bin/provisioner backup "/var/backups/shared-resource-provisioner/control-$(date -u +%Y%m%dT%H%M%SZ).db"
```

The destination must be new. The command creates a consistent snapshot, uses a
private parent directory (`0700`), and protects the backup file (`0600`). Store
an encrypted copy off-host using the operator's approved backup system. The
SQLite file contains control-plane metadata, grants, idempotency state, audit
facts, and secret references; it does not contain the service credentials held
by Ciphera. Restoring SQLite alone does not restore target clusters, Ciphera
projects/identities, TLS material, or operator-only target keys. Follow the
[host-loss recovery drill](docs/runbooks/host-loss-recovery.md) before enabling
mutations on a recovered instance.

## Production deployment

The production Docker Compose deployment, container build, host prerequisites,
configuration mounts, and update/backup procedure are documented in
[DEPLOY.md](DEPLOY.md). It is a single-node deployment and keeps mutations
disabled by default.

PostgreSQL endpoint files must contain a PostgreSQL URI; remote endpoints
require `sslmode=verify-full`. Its accepted query options are `sslmode`,
`sslrootcert`, `connect_timeout`, `application_name`, and
`target_session_attrs`. Valkey endpoints use a `redis://` URI only on loopback
and `rediss://` remotely. NATS endpoints use `nats://` only on loopback and
`tls://` remotely. Query parameters are rejected from Valkey/NATS endpoints.
