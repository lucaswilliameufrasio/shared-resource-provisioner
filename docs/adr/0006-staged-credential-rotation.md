# ADR 0006: Staged credential rotation across shared-service drivers

- **Status:** Accepted
- **Date:** 2026-10-18

## Context

Safe credential rotation requires the old credential to remain usable while a
new credential is created, stored, fetched by the workload, and adopted. The
existing drivers create one identity per resource; replacing its password in
place would invalidate running clients before an OIDC acknowledgement. The
user approved completing rotation for PostgreSQL, Valkey, and NATS, and selected
an OIDC polling endpoint for reference delivery.

## Decision

- Persist a monotonically increasing credential generation per resource and a
  durable rotation operation with states `staging`, `pending`, `finalizing`,
  `reconciliation_required`, `completed`, and `failed`.
- Stage a distinct target identity and a unique generation-scoped Ciphera key
  name for the next generation. Rotation secret names stay within the existing
  application/environment key prefix so the runtime's read-only scope remains
  applicable. This is an application-level immutable-reference contract: once a
  candidate becomes pollable, the provisioner never writes that generation key
  again; Ciphera-native immutable-version or conditional-create semantics are
  not assumed.
- Do not return the staged secret reference through MCP. An OIDC-authenticated
  workload polls the pending reference, fetches it through its own scoped
  Ciphera identity, and acknowledges the exact operation, reference, and
  generation. The provisioner never fetches or returns the value.
- Keep the active reference and old target credential until the exact
  acknowledgement is durably audited. Only then finalize the target-specific
  cutover and promote the new reference in SQLite.
- PostgreSQL stages a second login role with inherited resource privileges;
  after acknowledgement it transfers database/schema/object ownership and
  retires the previous login role. The database-level connection limit remains
  the cap while both identities overlap.
- Valkey stages a second ACL user with identical key/channel/command scope and
  deletes the prior user only after acknowledgement.
- NATS stages a generation-derived user identity under the existing resource
  account. The rotation history in SQLite supplies the complete set of retired
  user generations so every account JWT update preserves earlier revocations.
- A failed stage is compensated. If cleanup fails before acknowledgement, the
  candidate reference is not returned by polling and cannot be acknowledged;
  the resource remains `reconciliation_required` for operator cleanup. A failed
  post-ack cutover remains `reconciliation_required`; retrying the exact
  acknowledgement retries idempotent finalization. Revoke is blocked while a
  rotation is pending, but the explicit reconciliation path may revoke all
  recorded generations.
- Grants are exact and deny-by-default: callers need `rotate_resource`; the
  workload subject needs `adopt_rotation`. Both actions are scoped to the
  resource's application and environment.

## Consequences

- SQLite schema migration, backup/restore behavior, MCP contracts, HTTP OIDC
  routes, all target drivers, and integration tests change together.
- The target drivers must make generation-specific create/finalize/revoke
  operations idempotent across process restart and retry.
- A poll endpoint reports only safe references and metadata and must set
  `Cache-Control: no-store`.
- The callback proves the authenticated workload asserted adoption; it does
  not prove application health. Runtime integration and intended-environment
  testing remain required before production use.
- Rotation remains gated by `SRP_MUTATIONS_ENABLED` and must not be used against
  shared or production targets during local tests.
