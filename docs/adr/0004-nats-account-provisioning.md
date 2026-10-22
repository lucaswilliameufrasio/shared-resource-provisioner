# ADR 0004: NATS resource accounts and recoverable credentials

- **Status:** Accepted
- **Date:** 2026-10-14

## Context

NATS resources use JWT authentication. A resource account and its application
user must be recreated consistently after an interrupted create operation, and
the user must be revocable after process restarts. The control-plane database
must not hold user seeds or generated credentials.

## Decision

- Create a dedicated NATS account and user identity for each provisioned
  application/environment resource. The account is the subject-isolation
  boundary; the resource user may publish and subscribe within that account.
- Derive account and user seeds with HMAC-SHA-256 from the configured NATS
  operator seed and the stable resource ID, using different fixed purpose
  strings. Retries and revocation therefore recover the same identities without
  storing private keys in SQLite. The operator seed remains a high-impact
  credential and must be protected and backed up by the operator.
- Sign account claims with the operator key and user claims with the account
  key. Enforce configured account limits for connections, subscriptions,
  payload size, and—when enabled—JetStream storage, streams, and consumers.
- Publish account claims through the built-in NATS account resolver using
  `$SYS.REQ.CLAIMS.UPDATE` and the configured system-account credentials. Only a
  positive update acknowledgment is success; skipped, rejected, and timed-out
  updates enter the normal compensation/reconciliation path.
- Revoke resource users by publishing updated account claims containing their
  revocation timestamps. Credential rotation derives a separate user identity
  per generation under the same account and preserves prior revocations; the old
  user is revoked only after runtime adoption is acknowledged.
- NATS endpoints use TLS except on loopback. Operator seeds and system
  credentials are read from owner-only files and never returned or logged.

## Alternatives considered

- Random resource keys would require durable private-key storage or a separate
  secret-store read capability to make retries and revocation recoverable.
- Persisting user or account seeds in SQLite was rejected because the database
  must not contain credential material.
- Treating a `jwt update skipped` response as success was rejected because the
  account may not have been installed or updated in the cluster resolver.
- Exposing a generic NATS command or subject passthrough was rejected; callers
  receive only typed lifecycle operations.

## Consequences

- The NATS operator seed must remain available to the provisioner for signing
  and deterministic identity recovery; its compromise permits broad control of
  the operator's NATS trust domain.
- The configured NATS cluster must use a writable built-in account resolver,
  and its system identity must be authorized to update account claims.
- The local NATS integration test exercises claim installation, account
  isolation, connection and JetStream stream limits, retry identity, and
  revocation. It does not replace production target configuration review or an
  operational recovery drill.

## Revisit when

Revisit key derivation or account boundaries if the operator key is moved
offline, one account begins serving multiple application resources, or NATS
changes its supported account-resolver update protocol.
