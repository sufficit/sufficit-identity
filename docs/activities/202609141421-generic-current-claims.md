# Generic current-claim delivery and self-endpoint verification

## Scope

Correct business coupling introduced while preparing a consumer application's
customer access. This record completes that architectural correction, not the
consumer's wider deployment.

## Findings and changes

- Read-only published-issuer checks returned 404 for `/me` and 401 without
  authentication for `/connect/userinfo`. OIDC discovery identifies the latter.
- UserInfo already loads persisted claims. `/api/account/personal` returns profile
  fields; `/api/claims` requires management authorization.
- Removed product-specific defaults from `ServerResolvedEntitlementKeys` and
  GUID parsing from `ServerResolvedEntitlements`. Values remain opaque; bounds
  and exact key filtering are generic delivery rules.
- Retained the additive current-grant query on UserInfo, resolving direct and
  current Identity-role assignments for the validated subject only. Tests now
  use neutral examples and non-GUID resource values.
- Documented the business-agnostic boundary and external deployment configuration.

## Validation

`dotnet test src/tests/Sufficit.Identity.Tests.csproj --no-restore
-p:SufficitUseLocalSui=false --filter
'FullyQualifiedName~ServerResolvedEntitlementsTests|FullyQualifiedName~CurrentEntitlementsFlowTests|FullyQualifiedName~ClaimScopeMapTests'
-m:1 --verbosity quiet`: **24 passed**.

The first integration attempt used a configuration key outside `ClaimScopeMap`
and correctly returned no configured grants. Corrected the test and example to
`Sufficit:Identity:ClaimScopeMap:ServerResolvedEntitlementKeys`; integration then
passed with opaque values and same-token revocation.

## Delivery status

Source and documentation changed locally. No deploy, live grant assignment or
token issuance was performed. Production tokens were not changed. The consumer's
broader work remains tracked in its own plan.
See [current claim delivery](../operations/CURRENT-CLAIM-DELIVERY.md).
