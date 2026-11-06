# Activity — Holder-bound subject-token exchange

Date: 2026-11-06. Plan B3.1 source/test closure.

## Problem and correction

A legitimate holder of an opaque DPoP-bound subject token received HTTP 400 on
exchange. Re-enabling the existing skipped regression reproduced that failure.
The STS had calculated `ath` against OpenIddict's resolved payload rather than
the original token, then the dispatcher would consume the same proof again.

The original token is now retained per validation context before reference-token
resolution. After validation succeeds and the key matches the token binding,
the proof is handed to the dispatcher via a private single-consumption item in
the current HTTP context. The dispatcher still checks nonce validity and issues
challenges; no proof is reusable across requests. No replay-cache policy was
relaxed and no subject/actor token substitution is introduced by a shared raw
transaction token value.

Permanent contract: [DPoP documentation](../rfc/RFC-9449-DPOP.md).

## Evidence

- Before the fix: enabled holder regression failed, expected HTTP 200, actual 400.
- Locked package-mode restore: 14 projects, zero errors/warnings.
- `rtk dotnet test src/tests/Sufficit.Identity.Tests.csproj --no-restore
  -p:SufficitUseLocalSui=false --filter
  'FullyQualifiedName~TokenExchange|FullyQualifiedName~Dpop|FullyQualifiedName~DelegatedCredential'
  --nologo --verbosity quiet`: **110 passed, zero warnings**.
- Coverage includes the previously skipped holder success, output `cnf.jkt`,
  wrong key, missing proof, missing/wrong ath, replay refusal, fresh-proof success
  and required nonce challenge followed by successful retry.
- `MarkdownCoverageTests`: **8 passed, zero warnings**. `git diff --check`: clean.
- All three execution checkpoints completed.

Delivery commit title: `Fix holder-bound DPoP subject-token exchange` on main.
No production publication is included. The production consumer inventory gate
remains before rollout; the prior inventory is historical evidence only.
