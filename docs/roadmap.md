# Development roadmap

## Implemented

- Independent control-plane boundaries, SQLite resource/idempotency/grant/audit
  persistence, audited grant administration, and protected backup/restore tests.
- Ciphera `SecretStore` adapter with environment/project mapping and safe
  reference generation; generated values are not returned through MCP.
- PostgreSQL, Valkey, and NATS lifecycle drivers with per-target limits,
  compensating/reconciliation paths, and unit coverage.
- Typed planning, create, inspect, and revoke MCP actions. Mutations are
  explicitly gated and remain disabled by default; rotation is not exposed.
- Isolated PostgreSQL, Valkey, and NATS driver tests pass locally through
  `scripts/test-integration.sh`; CI now has a dedicated job to run the same
  isolated suite. A remote CI result is not available from this checkout.

## Accepted first-deployment choices

- Provision logical resources in operator-managed PostgreSQL, Valkey, and NATS
  clusters; do not install or operate the clusters themselves.
- Use SQLite for a single-node control plane. Store metadata, idempotency,
  grants, and append-only audit facts there; never store secret values.
- Manage resource grants through a REST admin API outside MCP. Bootstrap admin
  subjects with an exact OIDC `sub` allowlist in operator configuration; do not
  manage administrator membership through the API.
- Use signed OIDC JWTs for HTTP MCP, Ciphera as the selected secret backend, and
  Docker Compose as the first runtime. Operators preconfigure Ciphera projects
  and identities; trusted workloads use read-only, environment/prefix-scoped
  identities through `ciphera run`.
- Do not set global numeric quotas. Require service-enforceable limits per
  target before enabling its mutation driver; logical isolation is not a hard
  CPU, memory, or disk quota.

## Remaining readiness work

1. Keep the local quality gate and dedicated CI integration job passing.
2. Complete a control-plane host-loss restore drill and production deployment
   hardening; a remote CI result is not available from this checkout.
3. Validate Ciphera secret delivery and end-to-end compensation/reconciliation
   in the intended deployment environment.
4. Keep rotation disabled until runtime adoption acknowledgement is designed and
   tested. Complete operational monitoring, security review, and recovery
   procedures before production enablement.

Each mutation slice includes authorization, idempotency, audit, compensating or
reconciliation behavior, and tests against the real service before the MCP tool
is advertised.
