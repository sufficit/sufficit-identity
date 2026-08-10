# Vault — Fases 2 e 3 (fundação entregue)

**Data:** 2026-08-08
**Plano:** [`PLAN-VAULT.md`](../plans/PLAN-VAULT.md)

## Entregue

- tabela `vaultsecrets` com ciphertext, AAD e metadados de atualização;
- `VaultBackedSecretStore` com nomes seguros, round-trip e exclusão;
- API administrativa `/api/vault/secrets` com capabilities separadas,
  respostas write-only e auditoria de mutações;
- chaves RSA versionadas no vault, JWK público não sensível, `SignAsync`,
  `VerifyAsync` e rotação preservando assinaturas antigas;
- migrações EF e script SQL regenerado;
- testes de persistência, rejeição de nomes, assinatura e rotação.

## Pendências explícitas

- migrar consumidores de configuração (banco/certificados) para `ISecretStore`;
- migrar o backend de KEK para KMS/HSM externo e executar os ensaios de
  autorização da API em ambiente de produção (o provider OpenIddict/JWKS foi
  entregue em [`202608081530-vault-signing-provider-jwks.md`](202608081530-vault-signing-provider-jwks.md));
