# Email confirmation recovery

Date: 2026-11-09, America/Sao_Paulo.

## Problem and change

The reported confirmation page showed `Invalid token.` and offered only login.
Production logs confirmed four failed attempts on November 9, 11:36–11:54 local
time. They do not distinguish token expiration, security-stamp mismatch or
cryptographic rejection. The exact cause for the supplied link remains unproven;
no production confirmation link was replayed and no account state was changed.

The page now maps InvalidToken to the existing localized invalid/expired-link
message and other failures to a generic localized confirmation error. Failed
requests offer an outlined action to the existing resend form. That form retains
its verification and dispatch controls. Token validation is unchanged.

Reference lock/decision ledger: supplied screenshot and existing ConfirmEmail,
ResetPassword invalid-link recovery and resend form. Reuse SUIAlert/SUIButton,
existing layout and outlined secondary recovery action. No visual redesign.

## Validation

- Regression before change: valid link passed; invalid, expired, malformed and
  missing token cases failed on messaging/recovery.
- After change: 43 focused tests passed with no warnings across
  EmailConfirmationFormTests, PublicAuthenticationBoundaryTests,
  ExternalIdentityLinkingTests and MarkdownCoverageTests. Assertions cover actual
  SSR HTML and persisted confirmed/unconfirmed account state in isolated SQLite.
- `git diff --check` passed; Impeccable detector returned no findings.
- No graphical browser inspection or production deployment was performed.

## Delivery and limitation

Prepared for direct commit/push to main under the workspace maintainer rule.
This record accompanies the UI/test change in the same commit. Source delivery
is separate from deployment. A new confirmation link can already be requested
through the existing `/account/resendemailconfirmation` route.

The [investigation plan](../plans/PLAN-EMAIL-CONFIRMATION-INVALID-TOKEN.md) retains
incident limitations. Token issuance timing and provider-level evidence are still
needed to diagnose this specific rejection; the UI correction does not make an
invalid production token valid.
