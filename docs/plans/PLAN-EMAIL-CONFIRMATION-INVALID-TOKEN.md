# Email confirmation invalid token

## Objective and acceptance

Investigate the reported email-confirmation failure without consuming the supplied
production token or changing account state. Correct a demonstrated defect and
verify it with regression coverage; distinguish source delivery from deployment.

## Checkpoints

1. **Completed** — Inspect token generation/validation, production diagnostics
   and existing tests to establish the cause and the safe correction.
2. **Completed** — Implement the demonstrated correction and its regression test.
3. **Completed** — Run targeted validation, document evidence and limitations,
   commit and push only this task's changes to main.

## Constraints and validation

Preserve parallel work. Do not log token values or personal account details.
No production account mutation or deployment is implicit in this investigation.
Use `dotnet test src/tests/Sufficit.Identity.Tests.csproj` with focused filters
for affected behavior and Markdown coverage. Record blockers if the evidence
cannot establish why this particular production token was rejected.

## Investigation evidence and reference lock

Production journal shows four failed confirmations on 2026-11-09 at 11:36–11:54
America/Sao_Paulo. The existing info-level logs do not distinguish expiry,
security-stamp mismatch or cryptographic rejection; exact incident cause remains
unproven. Generation and decoding both use Base64Url(UTF8(token)). No supplied
production token was consumed and no account state was changed.

Demonstrated defect: the confirmation page prints raw Identity errors and offers
no resend route. Scope the correction to localized recovery, retaining token
validation. Reference lock: the supplied screenshot, current ConfirmEmail card,
ResetPassword invalid-link action and existing resend flow. Decision ledger:
reuse SUIAlert/SUIButton and the outlined secondary action; use the existing
localized invalid-link message; route recovery to the existing verified/rate-limited
resend form. No layout/token redesign.

## Implementation checkpoint

Regression before correction: 1 passed (valid link), 4 failed (invalid, expired,
malformed and missing token). The rendered confirmation page now uses localized
messages and the existing resend route. ASP.NET Identity token validation is
unchanged. Post-change focused validation is in progress.

## Validation and remaining limitation

- Before correction: UI regression 1 passed / 4 failed.
- After correction: 43 focused tests passed (EmailConfirmationFormTests,
  PublicAuthenticationBoundaryTests, ExternalIdentityLinkingTests,
  MarkdownCoverageTests), no warnings. Command: `dotnet test
  src/tests/Sufficit.Identity.Tests.csproj --filter
  'FullyQualifiedName~EmailConfirmationFormTests|FullyQualifiedName~PublicAuthenticationBoundaryTests|FullyQualifiedName~ExternalIdentityLinkingTests|FullyQualifiedName~MarkdownCoverageTests'
  --no-restore --verbosity quiet` (through RTK).
- Impeccable detector: no findings. `git diff --check`: passed.
- Actual SSR responses were verified; no graphical browser inspection was run.
- Blocker for exact incident diagnosis: existing production info logs contain only
  succeeded/failed. Token issuance date and detailed provider rejection evidence
  are unavailable. Do not infer that the UX correction repairs token validity.
- No account mutation, confirmation request replay, email dispatch or deployment
  was performed in production. Source delivery is the only mutation in scope.

All source-correction checkpoints are complete; delivery accompanies this plan
and the activity record in Git. Exact production-token diagnosis remains the
explicit evidence limitation above. No deployment is claimed.
