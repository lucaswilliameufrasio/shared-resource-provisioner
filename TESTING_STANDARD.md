# Testing standard

## Verified environment

- Go toolchain: 1.27.3 or newer. `govulncheck` reports GO-2026-6809 as
  reachable with Go 1.27.2; this standard-library vulnerability is fixed in
  Go 1.27.3.
- Unit tests use local files and in-memory MCP transport tests; they do not
  require Docker, PostgreSQL, Valkey, NATS, an OIDC provider, or production
  credentials.
- Integration tests use the pinned `postgres:17.6-alpine` and
  `valkey/valkey:8.1.3-alpine` images plus an in-process NATS server. Compose
  publishes only random host ports on `127.0.0.1`, creates no persistent
  volumes, and uses passwordless test-only service auth inside the disposable
  containers. Never point the tests at shared or production services.
- Tests create temporary files only through `testing.T.TempDir`; test data is
  removed by Go's test cleanup.

## Required checks

Run from the repository root:

```sh
gofmt -l .
go vet ./...
golangci-lint run ./...
go test -race -count=1 ./...
go build ./...
go mod verify
govulncheck ./...
./scripts/test-integration.sh
```

`gofmt -l .` must print no paths. The race-enabled test suite is the full unit
suite. `scripts/test-integration.sh` starts an isolated, uniquely named Compose
project, waits for local health checks, runs the tagged PostgreSQL/Valkey/NATS
driver tests plus provisioning/Ciphera protocol integration tests, and removes
only that project on exit. The PostgreSQL integration test additionally verifies
database/role isolation, connection limits, revocation, staged role overlap,
ownership transfer, and old credential retirement after acknowledgement.
Valkey verifies ACL scope, command policy, revocation, staged access, and old-user
retirement. NATS verifies account isolation, limits, retry identity, revocation
history across generations, and staged user cutover. Provisioning integration
uses the production Ciphera HTTP client against a local protocol fake and real
SQLite state to test secret delivery, compensation, and reconciliation. The
checked local tool versions are golangci-lint 2.14.0 and govulncheck 1.7.0.

## Future integration requirements

- Keep the isolated real-service suite passing locally and in CI. Service-level
  lifecycle tests cover authorization, idempotency, compensation, and
  reconciliation with real local SQLite and the production Ciphera client
  against a protocol fake; driver integration tests exercise actual PostgreSQL,
  Valkey, and NATS protocols. Intended-environment Ciphera validation remains a
  separate operator check.
- Keep OIDC runtime polling/acknowledgement, exact-scope authorization, durable
  replay behavior, restart recovery, and staged driver integration tests in the
  required gate whenever rotation changes.
- Reassess local storage and test-container impact before adding or running
  container-heavy suites; use the verified rootless Docker context when needed.
- Do not enable mutations in production until the configured target and Ciphera
  recovery path has been exercised in its intended deployment environment.
