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
