# ADR 0003: Single-node state and grant administration

- **Status:** Accepted
- **Date:** 2026-10-13

## Context

The provisioner needs durable resource metadata, idempotency state, grants, and
append-only audit facts, without putting secret values in its control-plane
store. The first deployment is a single control-plane instance; operators also
need to change caller grants without editing a policy file and restarting for
every grant update.

## Decision

- Use SQLite for resource metadata, idempotency, authorization grants, and
  append-only audit records. Secret values and resolved credentials never enter
  this database.
- Treat the control plane as single-node and single-writer for the first
  release. Do not claim multi-instance HA. Backups must use a SQLite-consistent
  method and be protected; the host-loss restore procedure must be tested before
  production use.
- Manage application/environment/action grants through a REST admin API outside
  the MCP surface. Grant checks remain exact-match, deny-by-default, and reject
  wildcard subjects, applications, and environments. Grant changes are audited
  atomically with their database mutations.
- Protect the admin API with the configured OIDC issuer and an exact allowlist
  of OIDC `sub` values supplied through operator configuration. The allowlist is
  not editable through the admin API. Admin bootstrap and recovery require an
  operator to update that configuration and restart the service.
- Do not expose grant-management or administrator-management MCP tools. The
  current planning-only executable continues to use its static policy file
  until the SQLite store and REST admin API are implemented.

## Alternatives considered

- A policy file for all grants was rejected as the long-term source because
  grant updates would require manual file edits and process restarts.
- Database-managed administrator roles were rejected for the first release:
  it would require a separate bootstrap credential and recovery path and could
  make the API capable of granting its own administrative authority.
- PostgreSQL/HA from the first release was rejected because the selected
  deployment is a single node and SQLite avoids another operational dependency.
  Revisit if multi-instance availability or write volume becomes a requirement.

## Consequences

- The SQLite schema and migrations must cover resources, idempotency, grants,
  and audit without accepting secret material.
- Admin identity changes are less convenient than database-managed roles but
  have a clear, out-of-band recovery path and cannot be performed by an API
  caller.
- The service must fail closed if the admin allowlist, OIDC validation, or
  persistent grant store is unavailable or invalid.
- Production readiness depends on tested backup, restore, and audit-retention
  procedures. SQLite single-node state is not a substitute for HA.

## Revisit when

Revisit the storage topology if the service needs multiple active instances,
cross-host failover, or a write workload that SQLite cannot safely support.
