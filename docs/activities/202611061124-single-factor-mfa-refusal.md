# Refuse single-factor evidence at MFA gates

Completed on 2026-11-06: the single-factor acceptance correction within A4.1.
The [authorization plan](../plans/PLAN-AUTHORIZATION.md) retains the broader
assurance/projection audit and browser chain. No deployment was performed.

## Finding and correction

PasskeyAssurancePolicy correctly omits `mfa` when user verification is absent,
but MfaEvidencePolicy accepted its `hwk` value alone. Isolated OTP and biometric
methods were also accepted. RFC 8176 section 2 distinguishes hardware-key
possession, OTP and biometric methods from the explicit `mfa` assertion:
https://www.rfc-editor.org/rfc/rfc8176.html#section-2

The shared policy now requires explicit `mfa`, or `pwd` plus a recognized
possession/biometric method from the existing compatibility vocabulary. Unknown
combinations fail closed and require explicit `mfa`. A remembered-device marker
never creates MFA by itself and still prevents the fresh-evidence check passing.
No new factor combinations or authentication mechanisms were added.

Compatibility: tokens containing only `hwk`, `otp`, `sms` or another single
method no longer satisfy MFA gates. External issuers must supply adequate evidence;
operators must reauthenticate when their existing evidence is insufficient.
This does not revoke tokens or deploy the change.

## Writer inspection and limits

- Interactive password sign-in emits pwd; remembered-device sign-in adds mfa and
  the remembered marker. TOTP and recovery-code completion emit explicit mfa.
- PasskeyAssurancePolicy adds mfa only with user verification; the service verifies
  the ceremony before setting successful authentication evidence.
- External sign-in adds mfa when the local remembered-device flow applies and
  records that marker; otherwise it emits federated/provider method names.
- The session factory and AuthenticationContextProjector propagate evidence.
  Their complete cookie/refresh chain is not established by these policy tests.
- AmrBasedAssuranceLevelResolver independently assigns its strongest level to hwk
  and other methods. This correction does not fix that mapping or the generic hwk
  label for passkeys. Both are explicit remaining A4.1 work.

## Validation and delivery

1. Completed: regression tests failed before correction: **24 failed, 65 passed**.
   Failures included emitted possession-only passkey methods, SCIM and Management
   gates, single factors and possession-only combinations.
2. Completed: corrected policy; **234 passed, zero warnings** across the selected
   authentication suites. Existing remembered and credential-mutation tests pass.
3. Completed: updated RFC consumption documentation and remaining plan scope;
   recorded this activity. Commit/push follows the direct-main repository workflow;
   this file's Git history identifies the delivered change.

```sh
dotnet test src/tests/Sufficit.Identity.Tests.csproj --no-restore -p:SufficitUseLocalSui=false --filter 'FullyQualifiedName~Scim|FullyQualifiedName~Mfa|FullyQualifiedName~RememberedSecondFactor|FullyQualifiedName~CredentialMutationSecurity|FullyQualifiedName~Passkey|FullyQualifiedName~AuthenticationContext|FullyQualifiedName~InteractiveSignIn|FullyQualifiedName~ExternalSignIn|FullyQualifiedName~MarkdownCoverage' --nologo --verbosity quiet
```

The passkey composition regression feeds authenticator flags through the real
method-emission policy and MFA consumers; it does not claim a browser ceremony
or production rollout was tested.
