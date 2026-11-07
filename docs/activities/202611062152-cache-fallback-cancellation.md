# Activity — Cancellation after failed cache read

Under the [runtime plan](../plans/PLAN-RUNTIME-ARCHITECTURE.md), added a deterministic
regression for cache read failure followed by cancellation during database fallback.
The test waits for the factory entry signal, cancels the caller token, verifies
OperationCanceledException and verifies that no cache mutation was attempted.
No sleeps or elapsed-time assertions were added.

Warnings-as-errors build and cancellation/session/synchronization checks:
22 passed. This complements the existing cancellation-before-fallback and
cancellation-after-durable-commit scenarios. The owned real Galera combined cache
failure and pooled-open results remain recorded in their activities; this test
uses a signaled factory and does not claim cancellation inside a live SQL driver.
No production change or deployment was made.
