# Session validity: from polling to notification

Every cookie-authenticated request verifies that the session is still valid by
reading the user's security stamp. That is one primary-key lookup, but it
happens on every request of every signed-in user, and it is how a revocation
takes effect: `SecurityStampValidatorOptions.ValidationInterval` is zero, so
nothing is cached.

`ISessionValidityCache` (`src/core/Sessions/`) lets a request skip that read
while two things hold at once:

- the ticket records a verification (`.identity.verified_at`) newer than the
  last known invalidation of that user, and
- the entry is younger than `UserSessions:ValidityCacheSeconds`.

## Why it is off by default

The cache is only consulted while `IUserSecurityChangePublisher` reports a
**connected** channel. A node that cannot hear about a revocation performed on
another node keeps reading the stamp, because the database is the only thing
all three nodes share. With `ValidityCacheSeconds` at its default of `0` the
server behaves exactly as it always has.

The window is the blast radius of a lost notification: for at most that many
seconds, one node may still accept a session another node revoked. Pick it
deliberately — seconds, not minutes.

## What invalidates

- `OpenIddictIdentityUserSessionRevoker.RevokeAsync` — every path that revokes
  a subject's sessions (password change, administrative revocation, credential
  mutation) drops the local entry and publishes to the other nodes.
- `UserSecurityNatsBridge` (`src/server/`) — applies what the other nodes
  publish. Same shape as `TrustedProxyNatsBridge`: best-effort notification
  beside an authoritative database, with the subject and payload validated
  before use. A hostile message can only ever cause **one more** stamp read,
  never one less.

## What is not covered

A mutation that rotates the user row without going through the revoker — a
lockout or a claim edit — is seen at the next principal refresh
(`PrincipalRefreshIntervalSeconds`) or when the window expires, not
immediately. That is the deliberate trade, and it is why the window is short
and the feature opt-in.

## Configuration

```jsonc
"UserSessions": {
  "ValidityCacheSeconds": 15,          // 0 disables; clamped to 0..300
  "Nats": {
    "Enabled": true,
    "Url": "nats://127.0.0.1:4222",
    "Token": "…",                      // from the secret store, not here
    "Subject": null                    // defaults per environment name
  }
}
```

Covered by `SessionValidityCacheTests` (the rules of the cache) and
`SessionValidityCacheIntegrationTests` (the validator: no channel means no
skipping, an invalidation brings the read back at once).

## Ticket-store request cancellation

`OidcUserSessionTicketStore` implements the token and HttpContext overloads of
`ITicketStore`. Explicit tokens reach database context creation, EF operations
and distributed-cache calls. Context overloads link the supplied token with
`RequestAborted`; legacy overloads use the current accessor's request token when
available. Outside a request, legacy callers retain non-cancelable behavior.

Cache operations link cancellation with their own bounded timeout. Cache timeout
may fall back to the authoritative database; caller cancellation propagates as
`OperationCanceledException` instead of starting a fallback read. Cancellation is
not rollback: a completed database mutation remains committed if a subsequent
cache operation is canceled. Invalidation may therefore remain pending until the
existing cache TTL; this change does not make database/cache updates atomic.

`SessionTicketCancellationTests` exercises all four operations via the interface,
explicit/context cancellation, cache-read cancellation without fallback, and
cancellation during cache writes/removal after a real SQLite commit.

## Browser-session persistence boundary

`IOidcUserSessionRepository` is the internal STS contract for durable session
operations; `OidcUserSessionRepository` uses a short-lived factory-created EF
context per call. Its singleton registration never captures a scoped context.
The repository reads detached session snapshots, upserts protected bytes, deletes
rows, touches activity, lists subject metadata and returns the IDs needed for
cache invalidation after subject deletion. All operations accept cancellation.

`OidcUserSessionTicketStore` owns serialization/Data Protection, request metadata,
expiry checks, the activity interval and distributed-cache policy. It no longer
queries EF directly. Its protector purpose and cache-key format are unchanged.

A touch attaches the previously read snapshot and changes only activity; it does
not overwrite a concurrently renewed protected ticket or insert a removed row.
Renewal uses one conditional update matching session ID and subject, without an
insert fallback. If revocation already deleted the row, renewal cannot recreate
it and the ticket store does not cache the rejected renewal. Creation/device
metadata remains unchanged. Fresh sign-in retains its separate upsert path.

Database mutation and cache writes are still not atomic: a renewal accepted
before revocation can write its cache entry after invalidation. The
subject-ID-selection/deletion sequence also remains unchanged. These races
remain in the runtime plan's F4.2/F4.3 scope.
