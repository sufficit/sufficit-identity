# Activity — Replica missing session invalidation

Date: 2026-11-06. Further F4.2/F4.3 evidence in the
[runtime plan](../plans/PLAN-RUNTIME-ARCHITECTURE.md).

## Delivered scenario

Extended the existing Redis promotion rehearsal into two independently named
tests sharing the same fixture. After confirmed initial replication, the new
case explicitly detaches/promotes the replica before revocation on the primary.
This prevents the replica receiving that deletion deterministically.

The primary's durable row and cache key are confirmed absent before primary
shutdown. A fresh client on the detached replica must observe exactly the
original protected bytes and can retrieve the stale ticket inside its TTL.
A renewal attempt must leave the durable row absent and the cache bytes unchanged.
At the original 15-second publication deadline (250 ms scheduling allowance),
both direct cache lookup and ticket retrieval reject the session.
Fresh sign-in after promotion still succeeds.

No application code was changed. The synchronization contract registers the
second real-TTL wait explicitly; no readiness sleep or clock-polling loop was added.

## Validation

Targeted acknowledged/missed promotion plus synchronization contracts:
**6 passed, zero warnings**.

Combined command enables both disposable-service opt-ins and runs:
`rtk dotnet test src/tests/Sufficit.Identity.Tests.csproj --no-build --no-restore
--filter 'FullyQualifiedName~SessionTicket|FullyQualifiedName~TestSynchronizationContractTests|FullyQualifiedName~OidcUserSessionRepositoryTests|FullyQualifiedName~ServerSideSessionsTests|FullyQualifiedName~InteractiveSignInServiceTests|FullyQualifiedName~SessionValidity'
--nologo --verbosity quiet`.
The assembly was built in package mode with SufficitUseLocalSui=false.
Redis executable: /tmp/identity-redis-rehearsal/redis-server (7.4.12).

Combined result: **67 passed, zero warnings**, including real Redis/MariaDB,
combined outage, replica promotion, clock-offset and cancellation cases.

MarkdownCoverageTests: **8 passed, zero warnings**. `git diff --check`: clean.
All three checkpoints completed; test processes/directories and containers cleaned.

## Limits and delivery

Explicit detachment models an invalidation omitted from a replica. It is not
Sentinel election, network packet loss, partition healing or Galera failover.
It intentionally documents possible stale access inside the configured TTL,
rather than asserting immediate revocation. Other HA/clock evidence stays pending.
[Architecture contract](../architecture/ARCHITECTURE-SESSION-VALIDITY.md).
No deployment or production infrastructure/session changes.
Delivery commit title: `Cover session invalidation missed by a promoted Redis replica`.
