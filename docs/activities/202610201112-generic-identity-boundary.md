# Generic Identity product boundary

Identity is a public, general-purpose identity provider. Consumer business rules,
domain roles and integrations belong in consumer applications. This constraint
is now permanent in PRODUCT.md, README.md and AGENTS.md.

Changes:
- Replaced provider-specific Vault/MCP examples and guidance with fictional services.
- Replaced references to a particular consumer/account in Vault UI resources and
  MCP instructions with the requesting application and authenticated Identity account.
- Clarified that namespaces organize secrets and do not grant access.
- Generalized business-specific claim fixtures, consumer names and comments without
  changing authorization or protocol compatibility behavior.
- Preserved package names, branding, attribution, configuration keys and existing
  compatibility contracts. Historical activity/deployment documentation was not rewritten.

Validation:
- 139 selected tests passed: Identity MCP, Vault, shared contexts, claim/scope mapping,
  delegated credentials, localization, client entitlements, device flow, token exchange
  and documentation contracts.
- Command: dotnet test src/tests/Sufficit.Identity.Tests.csproj
  -p:SufficitUseLocalSui=false --no-restore --verbosity quiet with the above class filter.
- Initial default-mode build failed with CS1704 because both local and packaged
  Sufficit.Blazor.UI assemblies were imported. The documented package-mode property
  resolved the validation issue without changing project dependencies.
- Existing NU1902/NU1903 warnings for cryptographic dependencies remain.
- Fixture JSON and both edited resource XML files parsed successfully.
- git diff --check passed.

Delivery: commit and push to main authorized by the user; no deployment requested.
The pre-existing untracked activity 202610192220-blazor-ai-bridge-migration.md was preserved.
