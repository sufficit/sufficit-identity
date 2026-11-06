# Activity — Shared management operation executor

Date: 2026-11-06. Scope: F2.1 in the [runtime plan](../plans/PLAN-RUNTIME-ARCHITECTURE.md).

## Implementation

Added the scoped `ManagementOperationExecutor` for capability demand and
best-effort audit persistence. Migrated duplicated helpers in Branding, Users,
Provisioning, Metrics, Sessions, Authorizations, Operator Tokens and Provisioning
Tokens. Thin service adapters preserve default capabilities/resource selection;
the evaluation, refusal and best-effort save implementations are shared.

Preserved the existing behavior:

- Branding, Users and Provisioning record each denied demand; Metrics, Sessions
  and Authorizations do not add denial writes.
- `ManagementOperationGuard` retains its specialized fresh-MFA and repeated-denial
  suppression policy. System-user fallback and credential issuance still use it.
- Successful mutation audit records remain at their original transactional sites;
  the executor does not open, commit or roll back an operation transaction.
- Best-effort persistence uses the same scoped DbContext, including any active
  transaction. Audit storage errors, including save cancellation, are logged and
  swallowed; evaluator cancellation propagates. This is not an isolated context
  or a durable outbox, and existing tracked-state behavior is unchanged.
- Failure logs from migrated audit helpers now use the shared executor category
  and include capability and correlation ID. Business-operation logs remain local.

No schema, endpoint, authorization requirement or production configuration change.
The shared F2.2 options contract was completed in its own earlier activity.

## Validation

- Release test build with `--no-restore -warnaserror`; existing focused
  Management/Branding/Provisioning tests: 396 passed.
- Six executor tests passed against SQLite: explicit repeated-denial audit choice,
  allowed demand without persistence, original refusal surviving audit storage
  failure, outcome audit rolling back with caller transaction, and evaluator
  cancellation without creating an audit row.
- Full Release suite (`--no-build --no-restore`): 2138 passed, 12 skipped,
  zero failures (2150 total, TRX counters). Final Markdown coverage: 8 passed.

## Delivery checkpoints

1. Implementation and focused regression validation completed.
2. Full regression and documentation validation completed.
3. Delivery record and diff review completed; commit/push verification is reported
   with the delivery result. Six pre-existing package-lock changes are excluded.

No deployment is claimed by this activity. The runtime plan remains open for F4.
