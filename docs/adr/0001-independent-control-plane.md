# ADR 0001: Independent provisioning control plane

- **Status:** Accepted
- **Date:** 2026-10-13

## Context

The shared-resource provisioner must remain a separate product from Uirapuru
and must not become a SQL-query MCP gateway. It needs a narrow, auditable MCP
surface for resource lifecycle operations across PostgreSQL, Valkey, and NATS.

## Decision

- Implement a standalone Go service in this repository. It has no dependency on
  Uirapuru APIs, MCP servers, SDKs, or lifecycle.
- Support both local MCP stdio and authenticated MCP Streamable HTTP. HTTP uses
  configurable OIDC issuer/audience validation and RFC 9728 Protected Resource
  Metadata discovery; stdio uses an explicitly configured local principal.
- Keep authorization in a common application layer, deny by default, and keep
  transport adapters thin.
- Expose typed lifecycle operations only. Do not expose SQL query, shell,
  Docker, or generic service passthrough tools.
- Implement shared-service logical isolation per application/environment:
  PostgreSQL database+role, Valkey ACL identity/prefixes, and NATS account.
- Begin with a non-mutating planning slice. Enable resource mutation only when
  persistence, auditing, secret-store integration, and real service drivers
  have integration coverage.

## Alternatives considered

- Extending Uirapuru was rejected because this tool must be independently
  deployable and outlive Uirapuru's API and lifecycle.
- Reusing a read-only SQL MCP gateway was rejected because query access is a
  different capability and does not safely provision resources.
- Generic command/SQL tools were rejected because they make authorization,
  validation, isolation, and audit boundaries unbounded.
- Supporting only stdio was rejected because authenticated remote MCP is an
  explicit requirement; supporting only HTTP was rejected because local MCP
  clients need a process transport.

## Consequences

- The first slice is deliberately planning-only; it cannot yet provision
  production resources.
- The same application use cases and authorization policy must serve both
  transports.
- OIDC configuration, a grant policy, TLS for non-loopback listeners, and
  protected service-target configuration are operational prerequisites.
- Each service driver must prove real protocol behavior and isolation before
  its mutation tools are exposed.

## Revisit when

Revisit the transport or control-plane topology if multi-node availability,
non-OIDC clients, or a runtime requiring a different remote protocol becomes a
concrete requirement.
