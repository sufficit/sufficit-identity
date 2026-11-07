# Activity — Kernel packet loss and runtime reconciliation

Date: 2026-11-06, 21:58 America/Sao_Paulo. Completed local work under the
[runtime plan](../plans/PLAN-RUNTIME-ARCHITECTURE.md).

## Real kernel loss and heartbeat

Added `scripts/check-nats-kernel-loss.py` and an opt-in integration test using the
real UserSecurityNatsBridge, two independent stamp caches and the validator.
The launcher creates a uniquely named NATS container with loopback-only published
port, pinned to `nats@sha256:b83efabe3e7def1e0a4a31ec6e078999bb17c80363f881df35edc70fcb6bb927`.
It verifies the container network namespace differs from the host namespace.
The test verifies the container PID before using sudo/nsenter/tc in that namespace.

After initial delivery succeeds, `netem loss 100%` drops all broker egress packets.
The test rotates a synthetic user's stamp and advances only the controlled cache
clock to its original 30-second deadline: validation rejects the old session.
It then awaits actual disconnect events using the production client's heartbeat
defaults, verifies publisher refusal while disconnected, removes netem and verifies
reconnection plus fresh invalidation delivery. A tc snapshot observed 183 dropped
packets during the run; the test also asserts a positive kernel drop counter.

Result: **1 passed**, observed duration about 6 minutes 2 seconds. The eight-minute
wait is a hang guard, not an asserted heartbeat SLA. The shared signaled logger
now accepts an optional timeout while retaining 30 seconds for existing callers.
The broker container and its namespace were removed by launcher cleanup. No
production broker, network interface or route was modified.

This extends earlier TCP relay tests with real kernel loss and default heartbeat.
It does not emulate a clustered broker, probabilistic packet loss or a production
network partition. Queued/retransmitted messages after restoration are not evidence
of durable notifications; the session bound remains independent of delivery.

## Other completed scope and validation

- [Redis placement](202611062149-redis-replica-placement.md): six live endpoints,
  cross-site replica mapping and healthy slot inventory, no production mutation.
- [Fallback cancellation](202611062152-cache-fallback-cancellation.md): new
  deterministic regression; 22 related tests passed, warnings-as-errors build.
- Full Release suite: **2,148 passed, 20 opt-in skipped**, total 2,168, zero failures.
  The kernel case ran separately above; older opt-in scenario evidence remains in
  its owning activities, not relabeled as executed by this full-suite run.
- Python compilation and whitespace checks passed. All eight Markdown coverage checks passed
  after linking this activity.
- Final production cluster check: all three apps active, Healthy health/readiness,
  unchanged certificate/JWKS pins, deployed revision e1aeb174.

## Remaining operational gate — not completed

F4 is not declared complete. The [ready-to-review HA procedure](../runbooks/RUNBOOK-RUNTIME-HA-VALIDATION.md)
sets out preflight, one-fault sequencing, abort/restore and evidence requirements.
Two concrete inputs are missing: the affected-consumer/maintenance/impact envelope
for shared Redis/Galera fault injection, and accepted observation/workload/error/
latency/skew thresholds. Those cannot be inferred from healthy snapshots or from
a general publication authorization. No production failure was injected here.

The existing request authorizes continued implementation and publication; it is
not treated as a reason to repeatedly request commit/push permission. This missing
operational definition is retained in the plan rather than silently moved away,
closed from local evidence or replaced by invented pass thresholds. All completed
local checkpoints are archived here; the whole plan remains open for that gate.
The six parallel lockfile changes remain excluded.
