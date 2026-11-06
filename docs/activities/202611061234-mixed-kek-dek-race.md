# Activity — Mixed KEK rewrap and DEK rotation race

Date: 2026-11-06. Plan C1.2 completed with regression coverage; no production
algorithm change was necessary.

## Controlled concurrency

Added a two-case theory to `VaultTests.KekRewrap.cs`. Independent KeyVault
instances and independent SQLite connections share one database. Each instance
uses its own certificate source, with the new KEK active and the old one retained
for reading. A test-only wrapper pauses the first wrap while its lifecycle lease
is held; bounded completion signals control the interleaving rather than sleeps.

- **Rewrap wins:** pause after acquiring the lease, require peer rotation to fail
  with the explicit lease-conflict exception, verify no version or completion
  journal was created by the loser, then release and retry rotation successfully.
- **Rotation wins:** pause rotation with its lease held, observe the rewrap retry
  timer being scheduled after a real lease conflict, release rotation, and require
  rewrap to succeed. The existing v1 is rewrapped; newly created v2 is already
  protected by the new KEK.

Both cases verify exactly versions 1 and 2, no leftover lease, one completion
journal, idempotent operation retry and old/new plaintext recovery through cold
vault instances configured with **only** the new KEK. This prevents in-memory key
caches from hiding an invalid persisted wrapping.

## Validation

- Focused mixed-race theory: **2 passed, zero warnings**.
- `rtk dotnet test src/tests/Sufficit.Identity.Tests.csproj --no-restore
  -p:SufficitUseLocalSui=false --filter
  'FullyQualifiedName~VaultTests|FullyQualifiedName~VaultSymmetricKeyLeaseTests|FullyQualifiedName~VaultSnapshotCacheTests'
  --nologo --verbosity quiet`: **72 passed, zero warnings**.
- `MarkdownCoverageTests`: **8 passed, zero warnings**. `git diff --check`: clean.
- All three execution checkpoints completed.

## Limits and delivery

This proves application coordination over independent connections in SQLite,
not network partitions, Galera replication behavior or a production key rotation.
All writing replicas must first switch to the new active KEK, as clarified in the
[vault runbook](../runbooks/RUNBOOK-VAULT.md); a lease does not stop a stale-config
node from writing under the old KEK after the operation.

Delivery commit title: `Cover concurrent KEK rewrap and data-key rotation` on main.
Only tests and documentation changed. No deployment or production key change.
