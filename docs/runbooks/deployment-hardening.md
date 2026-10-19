# Deployment hardening checklist

This checklist is a baseline for an operator-managed, single-node deployment.
It does not select a host, service manager, network topology, monitoring
backend, or production resource limits. Complete those choices for the intended
environment before enabling mutations.

## Process and persistent state

- Run one provisioner process under a dedicated unprivileged OS identity. Do not
  run the service as root or claim multi-instance SQLite high availability.
- Keep `SRP_SQLITE_PATH` on durable local storage in a directory owned by the
  service identity with mode `0700`. The database file must be `0600`; startup
  rejects broader directory or database permissions.
- Ensure the database path survives process/container replacement. Do not use an
  ephemeral container layer as the only copy of control-plane state.
- Configure the supervisor to send `SIGTERM`, not `SIGKILL`, for routine
  shutdown. The HTTP transport drains active requests for up to 60 seconds.
  Configure the supervisor/orchestrator termination grace to **more than 60
  seconds**, with additional platform margin (for example, 75 seconds), so it
  does not kill the process at the same instant as the application's deadline.
- A drain timeout is not proof that a mutation completed. The caller must retry
  with the same idempotency key; inspect operation/resource state and use the
  reconciliation path when reported. Forced host loss can still interrupt a
  request.

## Configuration and credentials

- Begin with `SRP_MUTATIONS_ENABLED=false`. Enable it only after target limits,
  Ciphera identities/projects, backup/recovery, and integration checks are
  approved for the environment.
- Keep target configuration, Ciphera configuration, endpoint files, NATS
  operator seed/system credentials, TLS key, and Ciphera service key outside the
  image and repository. Grant file access only to the service identity; mount
  files read-only where supported.
- Keep target administrator identities least-privileged and scoped to the
  operations each driver needs. Require explicit service-enforceable per-target
  limits; logical isolation is not a hard CPU, memory, or disk quota.
- Use separate credentials and Ciphera projects for each environment. Never use
  an application runtime's read-only Ciphera identity as the provisioner's
  write identity.
- Keep the exact OIDC admin-subject allowlist out of MCP arguments. Review grant
  changes and audit retention through the operator process.

## Network and transport

- Bind to loopback unless remote access is required. A non-loopback listener
  requires TLS certificate/key configuration and an HTTPS MCP resource URL.
- Restrict ingress to approved MCP and administration clients. Expose the admin
  REST API only to its intended operators; it is not an MCP tool surface.
- Restrict egress to the configured OIDC issuer/JWKS, selected PostgreSQL,
  Valkey, and NATS targets, and Ciphera API. Do not accept endpoints from MCP
  callers.
- Validate TLS trust, DNS, firewall rules, and certificate renewal from the
  intended host. Do not put bearer tokens or endpoint credentials in command
  arguments, shell history, or logs.

## Health, logs, and monitoring

- `GET /healthz` is a process-level liveness response; it does not prove that
  SQLite, OIDC, Ciphera, or target services are ready.
- The application writes structured JSON diagnostics to stderr. Configure
  bounded log retention and protect access. Alert on process restarts, HTTP
  shutdown failures, authentication/authorization failures, and
  reconciliation-required outcomes without logging credential values or raw
  upstream response bodies.
- The repository does not currently expose a metrics endpoint or target-aware
  readiness probe. Choose and validate an external monitoring approach before
  production enablement; do not claim observability is complete based only on
  `/healthz`.

## Release gate

- Run `TESTING_STANDARD.md` on the exact release candidate.
- Complete the [host-loss recovery drill](host-loss-recovery.md) on an isolated
  recovery host and record the approved RPO/RTO results.
- Exercise the configured Ciphera identity and each enabled target in an
  isolated intended-environment validation window. Never point local tests at
  shared or production resources.
- Obtain an operator security review of the host, secrets, identity scopes,
  network rules, backups, monitoring, and rollback procedure.
- Keep mutations (and therefore rotation) disabled until the intended runtime's
  OIDC identity, exact `adopt_rotation` grants, Ciphera key-prefix access, and
  environment-specific security/recovery checks have been reviewed. Local
  isolated tests are not authorization to enable production mutation.
