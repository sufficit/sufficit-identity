# Vault — provider de assinatura e JWKS (entregue)

**Data:** 2026-08-08
**Plano:** [`PLAN-VAULT.md`](../plans/PLAN-VAULT.md)

## Entregue

- provider `SecurityKey`/`ICryptoProvider` do IdentityModel que delega RSA-SHA256
  ao `IKeyVault`, sem exportar a chave privada;
- handler de emissão OpenIddict que seleciona a versão corrente do vault;
- handler JWKS que publica somente JWKs públicos não aposentados;
- `SigningKeyName` configurável (padrão `oidc-signing`) e guarda de ativação
  exigindo `Vault:Enabled=true`;
- rotação sobreposta preservando versões antigas durante a validação de tokens;
- testes unitários do provider e teste HTTP de JWKS com rotação v1/v2.

## Operação

`ManageSigningKeys=false` preserva o caminho de certificados existente. Para
ativar, aplique as migrações, habilite o vault e confirme todos os `kid`s no
endpoint `/.well-known/openid-configuration/jwks` antes de aposentar uma versão.
