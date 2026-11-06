# SCIM uses the shared MFA evidence policy

Completed on 2026-11-06: reader-consolidation portion of A4.1.
The [authorization plan](../plans/PLAN-AUTHORIZATION.md) retains the writer audit
and the separate browser-to-Management/SCIM chain. No deployment was performed.

## Changes

ScimAuthenticationContext delegates to MfaEvidencePolicy instead of maintaining
its own set of authentication methods. The SCIM authorization handler, denial
audit and destructive-operation policy continue using this same SCIM adapter.
Accepted evidence and remembered-device behavior are unchanged. Fresh MFA for
credential minting remains a separate policy check.

## Execution and validation

1. Completed: inspected consumers and added a characterization matrix covering
   all nine currently accepted methods, repeated/space-separated claims, missing,
   unknown and case-sensitive values, with and without remembered MFA.
2. Completed: replaced the reader; 50 characterization cases passed before the
   refactor, and the full targeted suite passed afterwards: **92 tests, zero warnings**.
3. Completed: recorded activity and narrowed the remaining plan item. Delivery
   uses direct-main commit/push; this file's Git history identifies the change.

```sh
dotnet test src/tests/Sufficit.Identity.Tests.csproj --no-restore -p:SufficitUseLocalSui=false --filter 'FullyQualifiedName~Scim|FullyQualifiedName~RememberedSecondFactor|FullyQualifiedName~CredentialMutationSecurity|FullyQualifiedName~MarkdownCoverage' --nologo --verbosity quiet
```

These are compatibility tests, not a claim that every accepted method alone
proves two independent factors. The writer inspection found a concrete combination
requiring follow-up: [PasskeyAssurancePolicy](../../src/sts/PasskeyAssurancePolicy.cs)
emits `passkey hwk` without user verification, while
[MfaEvidencePolicy](../../src/application/Sufficit.Identity.Application.Abstractions/Security/MfaEvidencePolicy.cs)
accepts `hwk`. The remaining A4.1 audit must validate this composition through the
actual authentication flow and resolve it with a regression test. This refactor
neither introduces nor resolves that existing behavior.
