# Development roadmap

## Implemented

- Independent control-plane boundaries, SQLite resource/idempotency/grant/audit
  persistence, audited grant administration, and protected backup/restore tests.
- Ciphera `SecretStore` adapter with environment/project mapping and safe
  reference generation; generated values are not returned through MCP.
- PostgreSQL, Valkey, and NATS lifecycle drivers with per-target limits,
  compensating/reconciliation paths, and unit coverage.
- Typed planning, create, inspect, and revoke MCP actions. Mutations are
  explicitly gated and remain disabled by default. HTTP additionally exposes a
  typed rotation action and OIDC-protected workload polling/acknowledgement;
  stdio omits rotation because it has no workload OIDC identity.
- Staged credential rotation for PostgreSQL, Valkey, and NATS, with distinct
  generation identities, unique Ciphera key names, durable exact-reference
  acknowledgement, idempotent finalization/abort, prior-credential retention
  until acknowledgement, and reconciliation after post-ack failures.
- Isolated PostgreSQL, Valkey, and NATS driver tests pass locally through
  `scripts/test-integration.sh`; CI has a dedicated job for the same isolated
  suite.
- Protected SQLite backup CLI, private-directory enforcement, and a local
  cross-directory restore test covering grants, resources, idempotency, and a
  pending staged rotation's operation/reference/version/generation. This local
  simulation does not replace the intended-host-loss drill.
- HTTP shutdown drains in-flight requests for up to 60 seconds; tests cover
  graceful drain, refusal of new requests, and bounded timeout behavior.
- Provisioning integration tests exercise SQLite and the production Ciphera
  client against an isolated protocol fake for secret delivery, compensation,
  and reconciliation.
- Driver integration tests exercise staged overlap and cutover against isolated
  local PostgreSQL, Valkey, and NATS services; provisioning tests cover the OIDC
  acknowledgement contract and retry/reconciliation paths.

## Readiness evidence

- The initial public commit is `0339060` on `main`. GitHub Actions run
  [38813563850](https://github.com/lucaswilliameufrasio/shared-resource-provisioner/actions/runs/38813563850)
  completed successfully on 2026-10-15, including the quality and isolated
  integration jobs.
- The local quality gate passed before that commit was pushed. Any follow-up
  code changes must pass the full local gate and their CI result must be checked
  before they are treated as verified. The current follow-up remains uncommitted
  on `feature/production-readiness`; no push was authorized.
- Follow-up verification passed locally on 2026-10-19: `gofmt -l .`, `go vet
  ./...`, `golangci-lint run ./...`, `go test -race -count=1 ./...`, `go build
  ./...`, `go mod verify`, `govulncheck ./...`, and
  `./scripts/test-integration.sh` (three consecutive fresh runs). The
  vulnerability scan found no reachable vulnerabilities; it reported one
  required module advisory not called by the analyzed code. Integration
  services were isolated local PostgreSQL/Valkey containers and an in-process
  NATS server.
- The SQLite backup command enforces the existing protected snapshot behavior
  and rejects a missing source database. The local cross-directory restore test
  is not an intended-host-loss drill.

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

1. **Operator-blocked:** complete the control-plane host-loss restore drill in
   the intended deployment environment. The operator must approve backup
   frequency, encrypted off-host retention, RPO/RTO, owner, and recovery host.
   The expanded local test verifies application data (including a pending
   rotation) but cannot establish host/storage/transfer properties or measured
   RTO/RPO.
2. **Operator-blocked:** validate Ciphera delivery and compensation/reconciliation
   against the configured tenant and target clusters in an explicitly isolated,
   authorized environment. Local protocol-fake and disposable-driver tests do
   not validate real identities, project mappings, network policy, or runtime
   key-prefix access. Do not use shared or production services for local tests.
3. **Operator-blocked:** complete environment-specific deployment hardening,
   monitoring, security review, and recovery procedures. Requires the intended
   host/runtime, network boundaries, service-enforceable limits, identity setup,
   monitoring destination, and an accountable reviewer. The repository checklist
   is a baseline, not evidence of an operator review.
4. Keep the complete local quality gate and CI jobs passing for every change;
   check CI after an authorized push.

Each mutation slice includes authorization, idempotency, audit, compensating or
reconciliation behavior, and tests against the real service before the MCP tool
is advertised.
