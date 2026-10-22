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
- The local quality gate passed before that initial commit was pushed. The
  follow-up is commit `cb0c79a` (`feat(rotation): add staged credential
  rotation`) on `feature/production-readiness`, pushed to `origin`.
- GitHub Actions run
  [39310730788](https://github.com/lucaswilliameufrasio/shared-resource-provisioner/actions/runs/39310730788)
  passed on 2026-10-19 for both `quality` and `isolated-integration`.
- For future code changes, rerun the complete local gate and check CI after an
  authorized push; do not treat cached or earlier checks as current evidence.
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
- Additional local validation passed on 2026-10-19 against a freshly built,
  disposable Ciphera server backed by an isolated PostgreSQL database. A
  temporary local service account/key and project exercised the provisioner's
  real Ciphera client together with disposable PostgreSQL, Valkey, and NATS
  targets: create, inspect, stage/poll/acknowledge rotation, and revoke. A
  protected SQLite snapshot restored into a separate local directory and a new
  read-only provisioner process recovered the grant/resource/pending-rotation
  state and planned without exposing mutation tools. This validates the real
  local service/API path, not the intended deployment's Ciphera identities or
  network policy; runtime OIDC JWT validation was not part of this drill.
- On 2026-10-21, HTTP authentication tests used a locally generated RSA signing
  key and an in-process OIDC issuer serving discovery and JWKS over loopback.
  The production verifier accepted a correctly signed token and rejected wrong
  audience, expired, and invalid-subject tokens; the real HTTP router accepted
  the valid token for rotation polling/acknowledgement and rejected a wrong-
  audience token. No external issuer or credentials were used. This validates
  verifier/router behavior, not deployment issuer configuration, TLS trust, or
  network policy.
- The complete Go quality gate passed again on Go 1.27.3. The isolated rootless
  integration suite passed three consecutive fresh runs. `govulncheck` reported
  no reachable vulnerabilities and one required-module advisory not called by
  analyzed code.
- A read-only SSH inspection of the previously checked shared host found the
  provisioner service inactive and no matching process/container. This is not
  evidence of an isolated deployment or recovery host; no host state was
  changed.
- A synthetic cross-host restore smoke test then passed on a distinct
  user-managed Linux host: a protected SQLite backup with fake references was
  transferred over SSH, restored under a new `0700` directory with a `0600`
  database, and its grant/resource/pending-rotation state was verified through
  the provisioner's persistence code. The actual provisioner binary started
  there in stdio mode with mutations disabled and no target/Ciphera config; MCP
  exposed only `plan_resource`, and a read-only plan call succeeded. All remote
  temporary files were removed. This proves cross-host file transfer and
  application restore on that host, not its isolation: a default route existed,
  and no production target routes, backup retention policy, or approved RPO/RTO
  were configured or tested.

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

1. **Cross-host recovery path validated; deployment criteria unverified:** a
   synthetic backup was transferred to a distinct remote host and restored;
   the restored grant/resource/pending-rotation state was verified and the real
   provisioner ran read-only there. This still cannot establish physical host
   loss, network isolation from production targets, off-host backup
   retention/independent access, or whether the measured recovery meets an
   approved deployment RPO/RTO.
2. **Locally validated; deployment-specific configuration unverified:** the
   real Ciphera client/service and all three drivers were exercised with
   disposable local identities/targets, and the production OIDC verifier plus
   HTTP rotation router were exercised against a signed local issuer. This does
   not establish the intended tenant/project identities, target mappings,
   runtime key-prefix access, deployed issuer/TLS trust, or network policy. Do
   not use shared or production services for local tests.
3. **Locally reviewed; deployment-specific evidence unavailable:** configuration
   validation, restrictive SQLite permissions, disabled-by-default mutations,
   audit/authorization paths, graceful shutdown, and structured logging are
   covered by code/tests and the local runbooks. The shared SSH host inspection
   was read-only and found no provisioner deployment; the separate-host smoke
   used no service or production configuration. Physical host/runtime
   boundaries, external monitoring delivery, and an accountable deployment
   security review remain unverified.
4. Keep the complete local quality gate and CI jobs passing for every future
   change. The Go 1.27.3 local gate, three rootless integration runs, and CI for
   the latest code commit passed; check CI again after documentation updates are
   pushed.

Each mutation slice includes authorization, idempotency, audit, compensating or
reconciliation behavior, and tests against the real service before the MCP tool
is advertised.
