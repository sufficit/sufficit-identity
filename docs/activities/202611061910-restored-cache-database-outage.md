# Activity — Restored stale Redis cache with MariaDB unavailable

Date: 2026-11-06. Partial F4.2/F4.3 evidence for the
[runtime plan](../plans/PLAN-RUNTIME-ARCHITECTURE.md).

## Delivered scenario

Added `SessionTicketMariaDbOutageTests.PersistedCache.cs` using the existing owned
loopback Redis process and disposable MariaDB container. The real ticket store,
repository, Redis cache adapter and MariaDB provider are exercised together.
No product-code behavior changed.

1. Persist a session and save an RDB snapshot containing its encrypted ticket.
2. Stop Redis, revoke the durable session through the store, and verify the row
   is absent before stopping MariaDB.
3. Restart Redis from the snapshot while MariaDB stays offline. Require byte-for-byte
   restoration of the cached ticket so an empty-cache restart cannot pass.
4. Observe stale cached acceptance. Renewal and new-session creation fail with
   the database connection error; a cold read also fails. No uncommitted session
   appears in cache, and repeated warm reads preserve the original ticket.
5. Wait for the original 20-second cache deadline. Verify the Redis key is absent
   and a read now surfaces database unavailability instead of returning a ticket.
6. Restart MariaDB, verify the revoked and uncommitted rows remain absent, and
   verify a renewal cannot recreate the revoked row or republish its ticket.
   A fresh sign-in is then cached and retrievable.

The single elapsed-time wait is explicitly registered in the synchronization
contract: it waits for the real Redis TTL to expire, not for background work.
Readiness and process lifecycle continue using the existing event-driven helpers.

## Validation

The new real-provider case, the three existing MariaDB/combined cases and four
synchronization-contract checks passed: **8 passed, zero warnings**. Command:

```sh
SUFFICIT_TEST_MARIADB_DOCKER=1 \
SUFFICIT_TEST_REDIS_EXECUTABLE=/tmp/identity-redis-rehearsal/redis-server \
rtk dotnet test src/tests/Sufficit.Identity.Tests.csproj -c Release \
  --no-restore -warnaserror \
  --filter 'FullyQualifiedName~SessionTicketMariaDbOutageTests|FullyQualifiedName~TestSynchronizationContractTests' \
  --nologo --verbosity quiet
```

Full Release regression: **2,140 passed, 17 opt-in tests skipped**, zero failures.
Markdown coverage: **8 passed**. `git diff --check` passed. No owned MariaDB
container or Redis process remained after the run.

All three checkpoints are complete; tests, architecture contract and this
activity are delivered together in the main-branch commit.

## Limits and delivery

A successful durable revocation cannot remove a stale snapshot while Redis is
offline. This test records the existing bounded acceptance contract; it does not
claim immediate revocation under cache restoration. Once that cache deadline
expires, no ticket is returned without authoritative storage. This differs from
the earlier combined tests that restarted Redis empty.

This is a local single-database/single-cache rehearsal, not a Galera or Redis
Cluster failover test. Production failover, simultaneous HA events, packet-loss
and clock-skew gates remain open. No production write or deployment occurred.
The six pre-existing lockfile edits are excluded from this task's delivery.
