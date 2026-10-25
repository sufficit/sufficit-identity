# Token maintenance release preparation

Authorized publication and testing. Release isolates the maintenance work from
unrelated claim-delivery edits. Local SUI source revision:
`09de575704b153d01958942e24a3c76f5c72b82a` (clean).

111 focused tests passed using local SUI. A new two-writer Galera 10.4.34
rehearsal also passed: 20 simultaneous claims with one winner, lease expiry,
takeover, stale-executor rejection and successful deletion by its successor.
The provider wraps certification deadlocks in InvalidOperationException; the
test recognizes the underlying MySQL 1213 as the losing contender. Workers
already catch failed passes and retry on their next poll.

Production initially has four Primary/Synced database members with one applier,
three healthy API hosts, and the external timer only on the designated owner.
The additive schema is absent and the previous migration is UniqueNormalizedEmail.
Cutover and production results remain tracked in the consolidated plan.

## Production deployment

Published source: commit `96fccc05375d75d6d0127fe1a6421ceb58e2406b`, PR #98.
Artifact `20261025-token-maintenance.tar.gz` SHA-256:
`3ccf6d95011adb517b442eb31f7cd92b9a3bcea2b6c04232b2536bcf3623aa4d`.
All three API hosts installed sequentially; each has the same REVISION and STS
SHA-256 `42d7f2c17fa1a8761a0ce134417bf67938ffdc67dbb983c975e398ba4f52ede8`.
Readiness, issuer discovery and login succeeded; maintenance API requires auth.

Migration 109 was applied once after schema-only backup, and its disabled row
was confirmed on all four Galera members. Cluster remains Primary/Synced, size 4,
with one applier. Runtime configuration and certificates were copied byte-for-byte
on each host; old binaries remain under `/opt/sufficit-identity.rollback-20261025`.
Systemd overrides were backed up under `/root/identity-maintenance-rollout-20261025`.

Removed the pruning override pointing to the separate pinned release. The existing
external job now uses `/opt/sufficit-identity/Sufficit.Identity.Server.dll`. Its
manual production validation completed at 2026-10-25T16:04:58.6434196Z: 383 tokens
and 1 authorization, exit 0. The subsequent watchdog also exited 0. These are
**CLI-mode** results, not a database-scheduled execution.

All integrated workers are deployed with RunInWebHost=true, but the seeded
database policy remains disabled. The external timer stays enabled until an
authenticated Management request can enable the policy and verify a managed run.
The repository's temporary-management-token skill requires that credential;
no operator token was minted or configuration row modified around that boundary.

Two isolated Galera containers and their dedicated network were removed after
validation. Production backups and the separate old release remain for rollback.

## Authenticated activation

The user supplied the scoped temporary token for this task. API policy PUT
returned 204 and execution POST returned 202. Both legacy timers were disabled
and their maintenance process was confirmed stopped before activation. The
managed run `ea1f7ca0d0f04faebe7d4d131e8ebd1e` succeeded at
2026-10-25T23:15:34.513565Z: 261 tokens, 0 authorizations. Next run is
2026-10-26T05:15:34.513565Z (30-day retention, six-hour interval).
No credential was saved to a file or published.

Full CI exposed two missing capability-help mappings in English/Portuguese.
The read/manage labels and detailed permission explanations were added; the
six existing presentation tests now pass. The other 1865 tests, browser job,
CodeQL and secret scanning had passed. A corrected release and fresh CI follow.
