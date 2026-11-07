# Activity — Owned weighted Galera quorum loss and recovery

Date: 2026-11-06, 21:07 America/Sao_Paulo. Extends the
[runtime plan](../plans/PLAN-RUNTIME-ARCHITECTURE.md) and
[causal-read activation](202611062102-galera-causal-read-activation.md).

## Scope and implementation

Added `--weighted-quorum` to `scripts/check-galera-causal-reads.py`. It creates
four uniquely named disposable containers on an internal Docker network, without
published SQL ports, using explicit voting weights 2/1/1/2. It pauses only its own
containers and removes them, their volumes and network in the existing finally
cleanup. It rejects combining this mode with `--identity-tests`.

Image: `mariadb@sha256:22edfe1c78349f8cae88bbb5c2873b7e6c515be767c91c691308ce57445806f3`.
Observed MariaDB 10.4.34, Galera provider 26.4.18(ra96793fc).
The fixture inherits dirty reads ON and sync-wait 14, with session-only preparation
for protected queries. The causal-wait timeout is two seconds in this fixture;
this is not a measurement of production timeouts.

## Observed result

`python3 scripts/check-galera-causal-reads.py --weighted-quorum` passed:

1. Four nodes formed a Primary component, reported total weight 6.
2. Pausing the first weight-2 node left three Primary nodes, reported weight 4.
   A row was deleted successfully and a protected peer read observed its absence.
3. Pausing the second weight-2 node left two non-Primary nodes. Each rejected the
   protected read, with errors 1047 and 1205 respectively. Legacy dirty reads
   still answered from those nodes. The non-Primary status reports weight 0;
   the model's surviving configured weights are 1+1.
4. Resuming the second node restored the three-node component. Resuming the first
   restored all four nodes and weight 6. Every protected read returned zero rows:
   the revoked row remained absent, including on the node paused before deletion.
5. Recovery recorded two 1205 errors and one 1047 on the first resumed node before
   its protected query succeeded. No successful stale result was accepted.

Initial execution exposed an over-specific assertion expecting only 1047:
causal waiting can instead return 1205. The next execution exposed a premature
recovery assertion: a resumed node can report a membership/Sync state before its
causal query succeeds. The final fixture accepts only these recognized errors
while waiting for recovery, bounded to 60 seconds per node; any successful but
stale answer fails immediately. This does not add retries to production code.

All three executions cleaned up their owned resources; final container and
network absence was checked explicitly. Python compilation and whitespace checks
passed. All eight Markdown coverage checks passed after linking this activity.
All three checkpoints are complete; remaining production gates stay in the plan.

## Production observation and limits

A fresh read-only cluster check after activation found all three application
nodes healthy, ready and active on e1aeb174, with unchanged certificate/JWKS hashes.
This is another point-in-time observation, not a sustained availability result.
No production configuration was changed or production fault injected here.

The fourth weight 2 is an explicit model choice consistent with the earlier
observed total; the Google production node's weight is not directly verified.
The scenario uses sequential process pauses and membership changes, not a
simultaneous 3-versus-3 network partition, kernel packet loss, HAProxy routing,
Redis cache or authenticated HTTP sessions. Provider quorum behavior does not
close F4's production/combined fault gates. Existing cache hits still bypass SQL.

The [architecture contract](../architecture/ARCHITECTURE-SESSION-VALIDITY.md#owned-weighted-quorum-rehearsal)
documents the command and convergence gate. Parallel workspace lockfile edits
were excluded from this change.
