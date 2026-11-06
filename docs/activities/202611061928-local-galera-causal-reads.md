# Activity — Reproduced stale cross-node reads on local Galera

Date: 2026-11-06. F4 evidence extending the
[production weights and causal-read observation](202611061918-galera-weights-routing-health.md)
and the [runtime plan](../plans/PLAN-RUNTIME-ARCHITECTURE.md).

## Reproducible probe

Added [check-galera-causal-reads.py](../../scripts/check-galera-causal-reads.py).
It accepts an image reference, never a database endpoint. It creates three owned
containers on a uniquely named internal Docker network, with no published host
ports, no production credentials and no shared data mounts. Finally it removes
its containers, their anonymous volumes and its network, including on failure.

Run from the repository root with Python 3 and Docker:

```sh
python3 scripts/check-galera-causal-reads.py
```

The default image is pinned to:
`mariadb@sha256:22edfe1c78349f8cae88bbb5c2873b7e6c515be767c91c691308ce57445806f3`.
Observed server version: `10.4.34-MariaDB-1:10.4.34+maria~ubu2004`.
Observed Galera provider: `26.4.18(ra96793fc)`.
Both match the versions observed on the accessible production nodes.

## Method and actual result

After all three nodes report Synced/ready with cluster size three, the probe
creates a disposable `rehearsal.sessions` table with one integer-key row. A causal
read first confirms that the reader received that row. It then desynchronizes
only the owned reader and holds a global read lock through a dedicated session,
preventing application of subsequent replicated writes while allowing reads.
A delete on another node succeeds before the following observations:

| Reader condition | Query setting | Observed result |
|---|---|---|
| Replicated apply blocked | wsrep_sync_wait=14 | COUNT = 1: deleted row still visible |
| Same block retained | wsrep_sync_wait=15 | SQL error 1205, no stale row returned |
| Lock released and desync disabled | wsrep_sync_wait=15 | COUNT = 0: deletion visible |

Only the local probe configures `repl.causal_read_timeout=PT2S` to bound the error
case. It asserts the actual SQL error, not a wall-clock performance threshold.
Infrastructure startup uses bounded readiness polling; the lock is acknowledged
by its owning SQL session. The [MariaDB provider reference](https://mariadb.com/docs/galera-cluster/reference/wsrep-variable-details/wsrep_provider_options)
documents the causal-read timeout; the [system-variable reference](https://mariadb.com/docs/galera-cluster/reference/galera-cluster-system-variables#wsrep_sync_wait)
documents the read bit missing from value 14.

## Harness corrections and validation

The first cluster attempt emitted a protocol message-length error with long
fixture names. It was explicitly interrupted by the agent using its identified
PID, cleaned up, and shorter names allowed the nodes to join. This was not a
manual user cancellation. The next attempt reproduced the stale read but its
30-second process timeout expired while the causal SELECT waited. The final
fixture bounds the Galera causal timeout itself; `lock_wait_timeout` was removed
because it did not bound that wait in the observed run.

Final probe exited zero with the results above. Python syntax compilation passed.
All eight Markdown coverage tests passed; `git diff --check` passed. No owned
Galera containers or networks remained. The three implementation/validation/
documentation checkpoints are complete and delivered together on main.

## Limits and next acceptance evidence

This is a real SQL replication probe using a minimal disposable session-like row,
not an execution of the Identity ticket store, cache, EF repository or HTTP flow.
It has three equally weighted nodes and no HAProxy, unlike the four-member
weighted production topology. It does not measure production failover or latency.

Effective settings on real Identity connections are still unobserved. The earlier
source search and global SQL settings cannot establish those session settings.
This local reproduction was prioritized before changing any runtime policy.
The next application-level evidence must cover cross-node repository reads and
revocation with the chosen session policy, timeout/cancellation behavior and the
failure path when the causal barrier cannot complete. Global production settings
were not changed; this is not evidence that a production user was affected.

The owning F4 plan remains open. Only this script, activity and plan updates are
in scope; the six parallel lockfiles are preserved. No deploy is involved.
