# Activity — Galera policy on reused physical connections

Date: 2026-11-06, 21:18 America/Sao_Paulo. Extends the
[runtime plan](../plans/PLAN-RUNTIME-ARCHITECTURE.md) and
[production policy activation](202611062102-galera-causal-read-activation.md).

## Gap and coverage

Existing owned Galera repository tests used `Pooling=false`, so they did not
exercise the documented logical-open behavior when the connector reuses a
physical session. Added an opt-in integration regression covering all four
combinations of `ConnectionReset=true/false` and synchronous/asynchronous EF open.
Each combination creates a unique application-name pool with maximum size one.

The test opens a protected EF connection, records `CONNECTION_ID`, and verifies
sync-wait 15 and dirty reads OFF. It deliberately resets that owned session to
sync-wait 14 and dirty reads ON before disposing its context. A control lease
without the interceptor confirms those unsafe values on the same physical
connection. The next protected EF lease must have the same `CONNECTION_ID`,
sync-wait 15 and dirty reads OFF. GLOBAL dirty reads remains ON. The test clears
only its own pool in finally; the launcher removes the owned cluster resources.

The initial control used the input connection string and opened a different
physical connection. The diagnostic identified the failed ID assertion; the
fixture now uses the actual EF/provider connection string for the control and
pool cleanup. The test then passed without weakening the same-connection
assertion or changing the production interceptor. The launcher now requests
normal console test diagnostics so failures include their assertion and stack.

## Validation

- Warnings-as-errors build plus policy/synchronization tests: **11 passed**.
- `python3 scripts/check-galera-causal-reads.py --identity-tests`: **2 passed**,
  including the four pooled combinations and the existing delayed-apply,
  fail-closed, revocation and recovery integration scenario.
- Real fixture: MariaDB 10.4.34 and Galera 26.4.18(ra96793fc), pinned image already
  recorded in the launcher; three owned nodes, no production endpoints.
- All eight Markdown coverage checks and `git diff --check` passed.
- No owned Galera containers or networks remained after the runs.

No product code, production configuration or deployment changed. This covers
session preparation at logical opens, not pooled connection recovery during a
network partition, endpoint failover or an authenticated HTTP journey. Those
remaining F4 gates stay open. Unrelated lockfile edits are excluded.

The implementation, validation and delivery checkpoints are complete; this
activity replaces the temporary checkpoint while the broader plan stays open.
