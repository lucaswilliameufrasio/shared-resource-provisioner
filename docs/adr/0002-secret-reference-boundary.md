# ADR 0002: Secret references, never secret values, cross MCP

- **Status:** Accepted
- **Date:** 2026-10-13

## Context

Provisioning generates application credentials, but the AI model must never
receive those values. The runtime still needs a safe way to consume credentials
without coupling the tool to Uirapuru.

## Decision

- Keep `SecretStore` as an internal write-only port; Ciphera is the selected
  concrete backend for the first release.
- A resource driver may create credential material internally and pass it only
  to the secret-store adapter. MCP DTOs, errors, logs, and audit events contain
  only safe metadata and opaque secret references.
- Do not provide an MCP `get_secret` operation. Runtime retrieval uses the
  selected secret backend's identity/reference mechanism, not the model.
- Use Ciphera directly as the first concrete backend. Operators pre-create and
  configure the Ciphera projects and service identities; the provisioner does
  not create or administer them. Its Ciphera write identity and project mapping
  come from protected server-side configuration, never MCP arguments.
- Use Docker Compose as the first runtime. A trusted host invokes Compose via
  `ciphera run` with a read-only identity scoped to the relevant environment and
  key prefixes. Ciphera injects plaintext into the child process/workload; this
  is not a boundary against workload code, the host administrator, or Docker
  daemon access. Do not use this delivery path for untrusted or agent-controlled
  workloads.
- No local plaintext or in-memory secret-store fallback is allowed. A driver
  and adapter may hold a generated value transiently while writing it to
  Ciphera, but Ciphera values are never persisted in provisioner metadata,
  logs, audit events, or MCP responses.
- Rotation is staged across distinct generation-specific target identities and
  secret names. The old identity and reference remain active until the runtime
  confirms adoption through the OIDC-protected HTTP callback recorded in
  ADR 0005. A failed staging attempt must delete its candidate key or remain in
  reconciliation.

## Alternatives considered

- Returning generated values once to the model was rejected because MCP
  transcripts and model context are not a secret-delivery channel.
- Storing credential values in provisioner metadata was rejected because it
  duplicates secrets and expands the control-plane attack surface.
- Returning credentials directly to Compose configuration or MCP was rejected:
  MCP/model context is not a secret-delivery channel, and storing values in
  Compose files would persist plaintext.
- Having the provisioner create Ciphera projects or identities was rejected for
  the first release; those remain operator-managed to keep the provisioner's
  Ciphera permissions bounded.

## Consequences

- The concrete Ciphera `SecretStore` adapter and Compose runtime binding are
  implemented, but intended-environment validation is still required before
  production provisioning can be enabled.
- Secret-store failure after a service resource is created must trigger safe
  compensation or a recoverable, non-active state; it must never fall back to
  returning the credential.
- The operator must provide and protect the Ciphera identities, project
  mappings, and runtime read-only tokens. The workload receives plaintext by
  design and must be trusted.
- Automated rotation requires exact runtime acknowledgement and unique
  generation-scoped secret names; an acknowledgement is an assertion by the
  authenticated workload, not independent proof of application health.

## Revisit when

Revisit the interface if Ciphera's API/identity model or the first runtime
changes, while preserving the invariant that credential values never cross
MCP.
