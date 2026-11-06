# PLAN — Deferred protocol roadmap

Status: queued; reviewed on 2026-11-06 against `a66456e`. No work item is in progress.

[Index and delivery rules](PLAN-IDENTITY.md) · [Item-by-item reconciliation](../activities/202611061100-plan-reconciliation-split.md)

## Scope and order

Optional demand-driven work after production/security gaps. SSF transport may reuse G1 infrastructure but has its own protocol delivery semantics.

## Acceptance

A consumer need and scoped design precede implementation; advertise only proven protocol behavior; optional items do not gate current production.

Operational statuses describe evidence still required; historical records are not
a fresh production inventory. Source/tests present does not mean deployed.

## G6 — Forward-looking protocol work

These remain optional roadmap work. Existing SSF dispatch is not a durable outbox; keep it distinct from administrative audit delivery.

Evidence: [README.md](../../conformance/README.md), [SharedSignalsDispatcher.cs](../../src/sts/SharedSignals/SharedSignalsDispatcher.cs).

- [ ] **G6.1 · deferred** — FAPI 2.0 Advancing Profile (needs encrypted request objects beyond JAR)
- [ ] **G6.2 · deferred** — Rich Authorization Requests (RAR — `authorization_details`)
- [ ] **G6.3 · deferred** — OpenID Federation (entity statements, trust chains)
- [ ] **G6.4 · deferred** — SSF durable outbox/retry state (persistent delivery guarantees beyond best-effort)

## Validation required when executing

Run the tests cited in the evidence and targeted regressions for the remaining
behavior. Record exact commands, outcomes, release/commit and limitations.
For UI changes use the repository design/browser workflow; for production gates
attach dated redacted evidence and rollback. Do not close an item solely because
a related type, test name or historical deployment exists.
