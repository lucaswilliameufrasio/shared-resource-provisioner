# ADR 0005: OIDC workload acknowledgement for credential adoption

- **Status:** Accepted and implemented; intended-environment validation pending
- **Date:** 2026-10-16

## Context

Credential rotation must not revoke the credential currently used by a running
application. The initial runtime consumes Ciphera references through
`ciphera run`, but there is no adoption acknowledgement contract. The user
selected an OIDC-authenticated workload callback as the direction for that
contract.

## Decision

- Runtime adoption acknowledgement will be a dedicated HTTP business action,
  separate from MCP tools and the administrator grant API.
- The workload obtains a pending reference by polling a dedicated OIDC-protected
  endpoint. The poll response includes the resource, rotation operation,
  credential name, generation-scoped reference, version marker, and generation;
  it never contains the credential value. The workload uses its own scoped
  Ciphera identity to load that reference and then acknowledges the exact
  operation/reference/version/generation.
- The callback must authenticate the calling workload with a signed OIDC token
  from the configured issuer and the provisioner's expected audience. The
  workload subject must have an exact, deny-by-default grant for the resource's
  application/environment and the acknowledgement action.
- An acknowledgement must identify the resource, the specific rotation
  operation, and the exact opaque revision/reference issued for that rotation.
  It must never contain credential material.
- A valid matching acknowledgement is idempotent, persisted atomically with an
  audit fact, and rejects stale, unknown, or mismatched revisions. The old
  credential remains valid until that acknowledgement is accepted; only then
  may the rotation workflow revoke it. Timeout or rejection leaves the
  rotation pending and recoverable.
- The pending reference is not returned by MCP. The workload poll and
  acknowledgement both require the exact `adopt_rotation` grant for the
  resource's application/environment.
- A rotation never overwrites the active secret. It uses a distinct generated
  key name for every resource generation under the same scope-hashed Ciphera
  key prefix. Staging retries may repair that not-yet-pollable candidate; after
  the pending reference is committed, the workflow does not write it again.
  This is an application-level immutable-reference contract, not a claim that
  Ciphera provides immutable versions or conditional-create semantics.
- Rotation is exposed only when mutations are enabled over HTTP; the stdio MCP
  transport omits it because it has no OIDC workload identity. This decision
  does not authorize production mutations.

## Alternatives considered

- A manual administrator acknowledgement was rejected as the adoption signal:
  an operator assertion is not evidence from the runtime that loaded the new
  reference.
- A new sidecar/agent was rejected for the first acknowledgement slice because
  it introduces another runtime component and deployment lifecycle; revisit if
  workloads cannot safely make the callback themselves.
- Immediate credential cutover was rejected because it can disconnect running
  applications before they load the new reference.

## Consequences

- The implementation includes a dedicated authenticated route, an exact grant
  action, durable rotation/revision state, replay-safe acknowledgement, and
  atomic audit behavior. Tests cover matching/mismatched acknowledgements,
  authorization, retry, and post-ack cutover recovery.
- Local tests cover matching and mismatched acknowledgement, wrong workload
  scope, replay, callback failure/retry, and old-credential validity before
  acknowledgement; the SQLite persistence test also verifies a pending rotation
  survives reopening the store. Intended-runtime OIDC and Ciphera validation
  remain operator checks.
- The local implementation uses unique per-generation Ciphera key names and
  returns an explicit generation version marker. Confirm runtime identity key
  prefix access and intended Ciphera semantics during deployment readiness.
- An OIDC callback records the workload's assertion that it adopted a
  reference; it does not independently prove that application code is healthy.
  Workloads and their OIDC identities remain inside the trusted computing
  boundary.

## Revisit when

Revisit this contract if the selected runtime changes, workload OIDC identity
cannot be scoped to the resource, or Ciphera provides a stronger native
adoption/version mechanism.
