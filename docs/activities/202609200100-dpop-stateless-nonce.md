# DPoP nonces: the handler was written for a store it was not given

Plan: `PLAN-IDENTITY.md` section B4, delivered and removed from it.

## What the item said, and what was actually there

B4 asked for a bounded grace set so a challenge would not invalidate a
legitimate retry, atomic issue/consume in the shared store, and tests for
multi-replica agreement and cross-client denial of service.

Reading the code before building any of that turned up three nonce stores:

| Store | State | Registered? |
|---|---|---|
| `ProtectedDpopNonceStore` | none — the nonce authenticates its own partition, expiry and entropy through Data Protection | **no** |
| `DatabaseDpopNonceStore` | one value per partition, in the protocol state table | yes, as primary |
| `DistributedDpopNonceStore` | one value per partition, in `IDistributedCache` | yes, validation only |

The token handler's own comment describes the first one: *"challenges a
cryptographically valid proof with a **stateless** nonce … invalid/anonymous
traffic cannot rotate another client's challenge."* The registration had
drifted to the second. The 2026-08-30 evaluation (F-4) replaced the
cache-only store with the durable one to fix multi-replica convergence — a real
defect — and did not notice that the handler above it had been designed around
a store that keeps nothing.

## The defect that drift produced

A store holding one value per partition answers a second challenge by
overwriting the first. The partition is endpoint, client and proof key, so
another client cannot do this to you — but you can do it to yourself: a client
with two token requests in flight is challenged twice, and its first retry
fails because of its second request.

Proven against the store the host actually resolves, before changing anything:
`A_second_challenge_does_not_invalidate_the_first` reported
`Expected: True / Actual: False`. The existing test
`Dpop_nonce_issuance_does_not_invalidate_concurrent_challenges` passed the whole
time, because it constructs `ProtectedDpopNonceStore` by hand — it was proving
the property of a class nothing used. The new tests resolve `IDpopNonceStore`
from the container.

## The change

`RollingDpopNonceStore` now issues through `ProtectedDpopNonceStore` and still
*validates* through the durable store and the cache, so a replica on the
previous release — which issues into those — keeps working for the sixty
seconds its challenge lives. Both become removable one release later.

Each B4 item, stated honestly:

- **Grace set** — by construction. Every nonce stays valid for its lifetime;
  issuing another displaces nothing.
- **Atomic issue/consume** — made unnecessary rather than implemented. There is
  no shared value to race on. Proof replay is a separate control, the atomic
  database `jti` cache, and is unchanged.
- **Rotate only after authentication and a plausible proof** — already true:
  OpenIddict authenticates the client before the handler runs, and the handler
  validates the proof structurally before it issues. With nothing stored there
  is no longer anything to rotate.
- **Multi-replica agreement** — through the Data Protection key ring, which the
  host persists to the database (`PersistKeysToDbContext`). The authentication
  cookies already depend on exactly this across the three production nodes, so
  it is not a new assumption. A test builds a second store from the same key
  ring and has it accept the first store's nonce.
- **Cross-client denial of service** — impossible without shared state; the
  partition test pins that a nonce is bound to one endpoint, client and key.

Reusing a nonce inside its lifetime is not a replay weakness: RFC 9449 §8 uses
the nonce to bound a proof's freshness, and the durable store allowed the same
reuse of its current value.

## Verification

1,463 tests pass, Release warning-clean, and the 23 DPoP tests include the
end-to-end dance — `use_dpop_nonce`, retry carrying the `DPoP-Nonce` value,
accepted. Three rolling-store tests were rewritten because they asserted the
behaviour being removed: one was named
`Rolling_nonce_store_issues_from_the_durable_primary`.

DPoP is off in production today (only mTLS is enabled, on eveo), so this
changes nothing live until it is turned on — at which point it removes a
failure clients would otherwise have hit under concurrency.

## Plan ids

This is the first section removed under the new rule that section ids are
stable: B4 leaves a gap, and B9 — cited by `conformance/README.md` — keeps its
name.
