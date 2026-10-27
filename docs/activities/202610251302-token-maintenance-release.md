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

At the initial deployment checkpoint, all integrated workers had
RunInWebHost=true and the seeded database policy was still disabled. The external
timer remained enabled until the authenticated cutover recorded below.
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

## Corrected release checkpoint

Artifact revision `9d8397ca98f01045b1777280564bd3a6f531e8c6`, SHA-256
`173dbdf58cd6f60b690cbfffd7d688ae14e0ba344c29e04e54de29380ef0c686`.
Two hosts were rolled sequentially and confirmed Healthy through the readiness
socket. The third host became unreachable on SSH and HTTPS over public IPv4,
IPv6 and VPN; the same failure was observed from another production host and
affected its infrastructure host too. The upload failed before any remote
mutation. Its last verified revision remains the initial feature release.
Do not claim the corrected artifact is installed on all hosts until connectivity
returns and the remaining rollout is verified. Original and corrected-release
rollback directories remain available. Public discovery still returns the
expected issuer. Both legacy timers are disabled on their former owner.

Corrected commit CI run 40244019123 passed: 1867 tests passed, 2 skipped,
0 failed; browser, production container, SQL rehearsals, API-only smoke and
dependency audit passed. CodeQL run 40244019122 and secret scanning passed.
Publication: [PR #98](https://github.com/sufficit/sufficit-identity/pull/98).

Final authenticated API read after rolling the two hosts confirms enabled=true,
retentionDays=30, intervalMinutes=360, no pending request or active lease, and
the successful managed run above. During the network outage the database
readiness check reports Primary/Synced, ready ON, cluster size 3 and one applier;
the earlier size-4 verification preceded that outage.

## Rollout closure — 2026-10-27

Connectivity recovered. The remaining host was still Healthy on revision
96fccc0 before the final rollout. Recovered the original corrected archive
from an already updated host and verified its SHA-256 against the recorded
value; no rebuild or schema change was needed. Preserved seven runtime
configuration/certificate files byte-for-byte, backed up overrides, and
retained the previous live directory for rollback.

All three hosts now report revision
`9d8397ca98f01045b1777280564bd3a6f531e8c6`, readiness Healthy, and identical
STS SHA-256 `146b647e5e48a16ab5c3efe577b1483297224c85361edc6c5d2f83d4384d3844`.
Public discovery on every host returns the expected issuer. Galera reports
Primary/Synced, ready ON and four members again. PR #98 checks for fbf02cc
passed (CI 40244470395, CodeQL 40244470405). The previously blocked rollout
is complete. No management policy or credentials were changed during closure.
