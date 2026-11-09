# Preserve pending email confirmation through claim changes

Date: 2026-11-09, America/Sao_Paulo.

## Problem and correction

Assigning custom claims during account onboarding rotated the security stamp
embedded in the already-issued email confirmation token. The incident timeline
showed issuance before claim assignments and subsequent confirmation failures.
An isolated regression reproduced the rejection for create, update and delete.

ClaimManagementService now preserves the security stamp while EmailConfirmed is
false, advances the concurrency stamp through UserManager.UpdateAsync, revokes
issued credentials and explicitly removes browser sessions through
ISessionManagement (including cached tickets). The existing bounded-cache
invalidation semantics of that service still apply. Permanent authorizations
remain valid. Confirmed accounts retain their existing stamp-rotation behavior;
credential/security mutations are unchanged. Claim values stay opaque and are
not copied into audit records.

This change cannot repair a link whose stamp was invalidated before the fix.
That account needs a fresh confirmation link after source publication and
production activation. No production token was replayed, email sent or account
modified by this work. The later reported failure after resend was not reproduced
from production evidence and is not claimed resolved by this regression.

## Validation and delivery

- Before correction: all 3 isolated create/update/delete regressions failed at
  real UserManager.ConfirmEmailAsync with the pre-mutation token.
- After correction: 20 claims/confirmation tests passed, no warnings.
- Expanded validation: 72 tests passed, no warnings, covering ClaimsControllerTests,
  EmailConfirmationFormTests, PublicAuthenticationBoundaryTests,
  ExternalIdentityLinkingTests, SessionSecurityStampValidatorTests,
  ServerSideSessionsTests, SessionsAndAuthorizationsControllerTests and
  MarkdownCoverageTests. Run with dotnet test src/tests/Sufficit.Identity.Tests.csproj,
  --no-restore --verbosity quiet and FullyQualifiedName filters for these classes.
- Regressions check real cached ticket removal, persisted refresh-token revocation,
  valid retained consent and successful confirmation from the original token.
- git diff --check passed. No schema or configuration changes are required.

All three plan checkpoints (reproduce, implement, validate/deliver) completed;
the temporary plan is retired into this record. Direct main commit/push follows
the workspace maintainer rule. This is source delivery; production deployment
is outside this correction.

See [management authorization](../architecture/ARCHITECTURE-MANAGEMENT-AUTHORIZATION.md)
and [application ownership](../architecture/ARCHITECTURE-SINGLE-SOURCE-UI.md).
