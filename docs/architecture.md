# Architecture and operating model

Status: the control-plane lifecycle, staged credential rotation, and OIDC runtime
adoption routes are implemented and tested against isolated local dependencies.
MCP mutations remain disabled by default; production use still requires
operator configuration and operational recovery/readiness review.

## Actors and responsibilities

- **Platform operator:** operates the existing PostgreSQL, Valkey, and NATS
  clusters; configures their endpoints and privileged identities, OIDC
  issuer/audience, the exact OIDC subjects allowed to administer grants,
  per-target limits, and the Ciphera project/identity mappings. These values
  never come from MCP tool arguments.
- **MCP caller:** plans and requests named resource lifecycle operations within
  its authorized application/environment scope; rotation is available only over
  the HTTP transport when mutations are enabled.
- **Application runtime:** Docker Compose workloads use Ciphera's read-only,
  environment- and key-prefix-scoped identity through `ciphera run`. Ciphera
  injects plaintext into the trusted workload's process environment; this is
  not an isolation boundary against the workload, host administrator, or Docker
  daemon. The runtime never asks the model to retrieve a credential.
- **Provisioner:** validates intent, authorizes it, coordinates service
  drivers, persists metadata/audit, stores generated credential material, and
  returns only resource metadata plus a reference.

## Journeys

1. **Plan a resource:** caller selects `postgresql`, `valkey`, or `nats`, and
   supplies application/environment names. The server validates the scope,
   authorizes `plan`, and returns the defined isolation model and proposed
   logical name. This operation is non-mutating and returns no secret material.
2. **Provision:** when an operator explicitly enables mutations, an authorized
   caller requests an idempotent named operation. The provisioner chooses a
   configured target in an existing cluster, creates the service-specific
   isolated identity/resource, stores generated credentials in the configured
   Ciphera project through `SecretStore`, persists metadata and an audit event,
   and returns a safe reference. Partial failures use compensation or
   reconciliation without returning credentials. The provisioner does not
   create or operate the underlying clusters or Ciphera projects/identities.
3. **Inspect:** authorized callers see bounded metadata and a safe secret
   reference. Connection strings and credential values are never returned.
4. **Rotate:** an authorized HTTP MCP caller starts a staged rotation. The
   provisioner writes the new credential under a distinct generation-scoped
   Ciphera key, while keeping the old target identity and reference active. The
   OIDC-authenticated workload polls `/v1/runtime/resources/{id}/rotations/pending`,
   loads the reference through its own scoped Ciphera identity, and posts the
   exact operation, reference, version, and generation to the acknowledgement
   route. Only a matching, audited acknowledgement allows target cutover and old
   secret cleanup. Rotation is omitted from stdio, which has no workload OIDC
   identity. A failed post-ack cutover remains in reconciliation; retrying the
   exact acknowledgement retries finalization. A candidate whose pre-ack
   cleanup fails is not returned by polling and requires operator reconciliation.
5. **Revoke:** caller supplies the stable resource identity and an
   explicit confirmation value. The service first disables access, records the
   transition, and then applies the configured cleanup/retention policy.

## Lifecycle and state ownership

The intended resource lifecycle is `planned -> provisioning -> active`;
rotation uses `active -> rotation_pending -> active`; revocation uses
`active -> revocation_pending -> revoked`. Failures are recorded with a stable
safe error code and a retry/reconciliation state. Resource metadata, operation
idempotency, and audit records belong to the provisioner. Service-specific
state belongs to the PostgreSQL, Valkey, or NATS target. Secret values belong
only to the selected secret store.

SQLite persists resource metadata, idempotency, grants, and append-only audit
records; secrets remain in Ciphera. The mutation gate is off unless
`SRP_MUTATIONS_ENABLED=true` and both target and Ciphera configuration files are
provided. Rotation is exposed only when mutations are enabled and the HTTP
transport is used; the workload subject needs an exact `adopt_rotation` grant
for the resource scope. Production enablement remains an explicit operator
decision after recovery and target readiness checks.

The SQLite database and its containing directory must be owner-only (`0600`
file, `0700` directory). HTTP shutdown stops accepting new requests and drains
in-flight requests for up to 60 seconds, enough for the configured 45-second
operation timeout plus the 10-second cleanup window and a small margin. The
service manager must grant a longer termination window; see the deployment
hardening checklist. A forced stop after a drain timeout may leave an operation
pending for idempotent retry or reconciliation.

## Module boundaries

- `domain`: validated resource kinds, application/environment scope, lifecycle
  metadata, and safe plans.
- `authorization`: principal/action/scope policy; deny by default. Grants are
  persisted in SQLite and administered through a separate authenticated REST
  API.
- `planning`: validates and authorizes plan requests and constructs the safe
  isolation plan.
- `secrets`: `SecretStore` port that accepts generated bytes internally and
  returns an opaque reference; no read/get method is exposed to MCP handlers.
- `audit`: append-only operation facts, excluding request bodies, credentials,
  and connection strings.
- `drivers`: explicit typed PostgreSQL, Valkey, and NATS operations, including
  generation-specific staged rotation and idempotent finalization/abort. A
  driver cannot accept arbitrary SQL/commands from a caller.
- `transport/mcp`: maps named MCP tools to use cases. It is an adapter only.
- `transport/http`: Streamable HTTP MCP, OIDC authentication, health probes,
  strict listener configuration, a separate REST admin surface, and protected
  runtime rotation polling/acknowledgement routes (never exposed as MCP tools).
- `transport/stdio`: local process identity and MCP stdio lifecycle.

## Isolation contract

- PostgreSQL: one database and generation-specific least-privilege login role
  per application/environment; role privileges/ownership transfer only after
  acknowledgement.
- Valkey: generation-specific ACL identities per application/environment,
  restricted to the
  assigned key and channel prefixes and required commands.
- NATS: one account boundary and generation-specific user identities per
  application/environment, with
  JetStream limits scoped to that boundary when enabled.
- Targets and their endpoints are selected from server-side configuration;
  callers cannot submit hostnames, ports, DSNs, or credentials.
- The provisioner manages logical resources only. Operators install, operate,
  and configure the existing service clusters.
- These are logical isolation boundaries, not per-tenant CPU, memory, or disk
  quotas. Hard resource guarantees require a dedicated target or a service
  feature that provides enforceable quotas.
- No global numeric quotas are selected. Each target must have an explicit,
  service-supported limit profile before its mutation driver is enabled; a
  driver must not claim a limit that its service cannot enforce.

## Transport and security contracts

- stdio uses the OS process boundary and a configured principal. The MCP
  protocol owns stdout; diagnostics go only to stderr.
- HTTP uses Streamable HTTP, OIDC issuer discovery, OAuth Protected Resource
  Metadata (RFC 9728), signature/issuer/audience/expiry validation, and
  subject-based authorization. The listener defaults to loopback. A
  non-loopback listener requires TLS configuration.
- The initial OIDC verifier accepts signed JWT bearer tokens with a subject,
  expiration, and configured audience. Opaque-token introspection is not yet
  implemented; do not configure an issuer that requires it.
- Both transports pass an explicit principal to the same authorization layer.
  Missing/invalid identity or missing grants is denied.
- Grant administration is a REST API outside the MCP surface. It is protected
  by the configured OIDC issuer and an exact-subject admin allowlist loaded from
  operator configuration. That allowlist cannot be changed through the API;
  recovering admin access requires an operator config change and restart.
- Resource grants are stored in SQLite and remain exact-match, deny-by-default
  grants without wildcard subjects, applications, or environments. Every grant
  mutation is audited.
- The MCP surface contains only named domain tools. It has no arbitrary SQL,
  shell, Docker, filesystem, or generic service-command operation.
- Responses and audit events exclude credential values, admin connection
  strings, raw upstream errors, and request payloads. Errors are classified
  into stable safe codes.
- Ciphera is the selected `SecretStore` backend. Operators preconfigure the
  Ciphera projects and service identities; the provisioner stores only their
  mapping/configuration and safe references, not secret values in SQLite.
- For Docker Compose, `ciphera run` uses a read-only Ciphera identity scoped to
  the relevant environment and key prefixes. Plaintext is delivered to trusted
  workload processes, never to MCP or model context. This does not protect
  plaintext from the host, Docker daemon, or workload code.
- HTTP accepts signed JWT access tokens from the configured OIDC issuer; opaque
  token introspection is not part of the selected initial deployment.

## Open integration decisions

The product-level choices below are settled. The remaining operational work
must be completed before enabling production provisioning:

1. Configure existing service targets, privileged identities, and enforceable
   per-target limits; protect all owner-only secret files and Ciphera identities.
2. Complete the control-plane host-loss restore drill and validate protected
   SQLite backups in the intended deployment environment.
3. Validate Ciphera delivery and end-to-end compensation/reconciliation in the
   intended environment; the local protocol fake does not validate the configured
   tenant, identities, project mappings, or runtime key-prefix grants.
4. Complete deployment hardening, observability, security review, and operational
   recovery procedures for each enabled target.

The code may define stable ports and validation independent of these choices;
it must not ship a production default that logs, returns, or stores raw secret
values outside a secret-store implementation.
