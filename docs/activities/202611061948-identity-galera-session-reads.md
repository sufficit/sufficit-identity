# Activity — Identity session reads on owned Galera

Date: 2026-11-06. Extends the [SQL causal-read probe](202611061928-local-galera-causal-reads.md)
under the [runtime plan](../plans/PLAN-RUNTIME-ARCHITECTURE.md).

## Implementation and scope

Added `SessionTicketGaleraIntegrationTests` and an `--identity-tests` mode to
[the owned cluster launcher](../../scripts/check-galera-causal-reads.py).
This mode publishes dynamically assigned SQL ports only on loopback, creates a
unique Docker bridge and passes two owned connection strings to the test process.
The original SQL-only mode retains its internal network without published ports.
Both modes remove owned containers/volumes/network in the cleanup path.

The integration test uses the actual EF AppDbContext, MariaDB provider,
OidcUserSessionRepository, OidcUserSessionTicketStore and data protection. Each
client has an independent in-memory distributed-cache implementation. A test-only
connection interceptor adds bit 1 to the existing wsrep_sync_wait value. This
comparison does not install any production policy or change product code.

After initial replication is confirmed with a causal read, the test freezes apply
on the reader, revokes through the writer's real ticket store and verifies absence
on the writer. It then checks the inherited configuration's repository read and
cold ticket-store read, including publication of the stale protected ticket to
that reader's cache. The causal cold read must surface MySqlException 1205 without
populating its cache. After releasing the block it must return no ticket, and
renewal must not recreate the removed row. The already populated stale cache is
checked separately: a database barrier does not retroactively invalidate it.

## Invocation

Build the Release test assembly first, then run the owned integration mode:

```sh
dotnet build src/tests/Sufficit.Identity.Tests.csproj -c Release --no-restore
python3 scripts/check-galera-causal-reads.py --identity-tests
```

Requires Docker and Python 3. Uses the previously pinned MariaDB 10.4.34 image
with Galera 26.4.18, three equally weighted nodes and a two-second local causal
wait timeout. Do not supply external endpoints to emulate this launcher: the test
issues locks and creates/drops a unique database; it is intended only for the
owned disposable containers. Its connection gate accepts loopback addresses.

## Validation

Owned Galera integration: **1 passed, zero skipped**, with actual MariaDB
10.4.34 and provider 26.4.18. Ordinary Release suite: **2,140 passed, 18 opt-in
tests skipped**. Four synchronization checks passed after a warnings-as-errors
build. Python syntax compilation and all eight Markdown coverage checks passed.
Whitespace validation passed; no owned Galera containers or networks remained.
The three implementation/validation/documentation checkpoints are complete and
delivered together on main.

The initial application launch could not discover published ports on Docker's
internal network and failed before executing the test. The fixture was changed
to a dedicated bridge with loopback-only port publication for application mode;
SQL-only mode retains the internal network. Resources from that attempt were
removed before rerunning.

## Limits and remaining work

This does not exercise browser/cookie middleware, the security-stamp validator,
Redis, HAProxy, weighted membership changes or production connection settings.
The SQL apply block deliberately makes the stale-read path reproducible. It is
not evidence that a production user experienced that path. A production barrier
policy, its cancellation/timeout behavior and cache invalidation consequences
remain a separate implementation decision backed by this comparison. Global
production database settings were not changed, and nothing was deployed.

Six parallel lockfile edits remain outside this task's delivery.
