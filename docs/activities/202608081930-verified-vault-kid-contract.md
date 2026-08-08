# Vault — contrato de `kid` verificado

**Data:** 2026-08-08
**Plano:** [`PLAN-VAULT.md`](../plans/PLAN-VAULT.md)

## Resultado

A divergência observada no endpoint JWKS não se reproduziu após recompilar a
árvore atual. O contrato de identificação das chaves gerenciadas pelo Vault
permanece versionado e estável:

- a primeira chave publicada usa `vault:oidc-signing:1`;
- após a rotação, as versões `vault:oidc-signing:1` e
  `vault:oidc-signing:2` permanecem disponíveis para validação sobreposta;
- chaves auxiliares publicadas pelo OpenIddict continuam coexistindo no JWKS
  sem substituir os `kid`s versionados do Vault.

Não foi aplicado um patch especulativo nem alterada a rotação em produção.
Assim, as alterações paralelas existentes no worktree permanecem intocadas.

## Evidência

Executado em `main`:

```text
dotnet test src/tests/Sufficit.Identity.Tests.csproj --no-restore \
  --filter FullyQualifiedName~Vault_managed_signing_publishes_versioned_jwks_endpoint
Resultado: 1 aprovado

dotnet test src/tests/Sufficit.Identity.Tests.csproj --no-restore \
  --filter FullyQualifiedName~VaultTests
Resultado: 20 aprovados, 0 falhas
```

O teste cobre publicação inicial, rotação e retenção da versão anterior. A
falha anterior foi classificada como divergência transitória do build/teste
paralelo, não como quebra reproduzível do contrato de `kid`.
