# PLAN — Account email identity and recovery

Status: queued; reviewed on 2026-11-06 against `a66456e`. No work item is in progress.

[Index and delivery rules](PLAN-IDENTITY.md) · [Item-by-item reconciliation](../activities/202611061100-plan-reconciliation-split.md)

## Scope and order

Keep a single implementation owner for the F9/F15 race matrix. Backfill/dual-write and parity checks precede the flagged lookup switch. G5 is an operator decision.

## Acceptance

Unique normalized confirmed identities, compatible primary-email mirroring, recent-authentication/confirmation controls and race-tested login/recovery/SCIM behavior.

Operational statuses describe evidence still required; historical records are not
a fresh production inventory. Source/tests present does not mean deployed.

## F9 — Unambiguous normalized email identity

Unique lookup and duplicate-email rejection tests exist; a multi-entry-point concurrency matrix is still needed and is shared with F15.

Evidence: [AccountLookupPolicyTests.cs](../../src/tests/AccountLookupPolicyTests.cs), [108-unique-normalized-email.sql](../migration/sql/108-unique-normalized-email.sql).

- [ ] **F9.1 · partial** — Complete the registration, SCIM-update, email-change, login and recovery race matrix. Unique lookup and duplicate-email rejection already have tests; F15.8 reuses this matrix.

## F15 — Multiple email addresses per account

Only the design exists: current lookup uses users.Email and UpdateProfile uses SetEmailAsync. No useremails migration/service/routes were found; 110 is a proposed number, not a reserved allocation.

Evidence: [ARCHITECTURE-ACCOUNT-EMAILS.md](../architecture/ARCHITECTURE-ACCOUNT-EMAILS.md), [AccountLookupPolicy.cs](../../src/sts/AccountLookupPolicy.cs), [UserManagementService.Profile.cs](../../src/management/Users/UserManagementService.Profile.cs), [109-add-token-maintenance.sql](../migration/sql/109-add-token-maintenance.sql).

- [ ] **F15.1 · pending** — Add useremails with a unique normalized address and primary-email backfill. The design proposes migration 110; allocate the next unused number at implementation time and keep canonical SQL/EF parity.
- [ ] **F15.2 · pending** — `IAccountEmailService` as the only writer; dual-write `users.Email`; `UpdateProfile` email change routed through it
- [ ] **F15.3 · pending** — Parity check between `users.Email` and the primary row as a posture finding
- [ ] **F15.4 · pending** — `AccountLookupPolicy` reads confirmed rows only, behind a flag
- [ ] **F15.5 · pending** — Management routes under `api/users/{id}/emails` (`identity.users.update`) and console page
- [ ] **F15.6 · pending** — Self-service `/manage/emails` with confirmation link, recent authentication and notification of the previous primary
- [ ] **F15.7 · pending** — SCIM full `emails[]` mapping per client trust
- [ ] **F15.8 · dependency** — Execute the F9.1 race matrix against the new email service and add confirmed-only/non-resolution/backfill tests from the account-email design. Reuse shared tests rather than duplicate them.

## G5 — Confirmed-email rollout **(operational)**

Unused-account purge is implemented. Treatment of used-but-unconfirmed accounts remains a decision based on a fresh inventory, not on historical account counts.

Evidence: [UnconfirmedAccountPurgeWorker.cs](../../src/management/Users/UnconfirmedAccountPurgeWorker.cs), [202610231500-plan-reassessment.md](../activities/202610231500-plan-reassessment.md).

- [ ] **G5.1 · decision** — Inventory currently used accounts with unconfirmed email and decide between authorized bulk confirmation and reconfirmation. The unused-account purge is implemented; historical counts are not current evidence.

## Validation required when executing

Run the tests cited in the evidence and targeted regressions for the remaining
behavior. Record exact commands, outcomes, release/commit and limitations.
For UI changes use the repository design/browser workflow; for production gates
attach dated redacted evidence and rollback. Do not close an item solely because
a related type, test name or historical deployment exists.
