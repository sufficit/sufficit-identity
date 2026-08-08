# Vault interno — Fase 1 implementada

**Data:** 2026-08-08
**Plano de origem:** [`PLAN-VAULT.md`](../plans/PLAN-VAULT.md)

## Entrega

- envelope encryption AES-256-GCM com ciphertext auto-descritivo e AAD;
- chaves versionadas persistidas em `vaultkeys`, protegidas pelo Data
  Protection key-ring;
- `IKeyVault` com modo compatível `pt1.` e rotação sem invalidar blobs antigos;
- `SsfStreamStore` cifrando tokens de autorização com `stream_id` como AAD;
- `DistributedDpopNonceStore` e `DistributedCibaPendingRequestStore`
  cifrando payloads de cache com AAD específico e aceitando valores legados
  durante rolling deployment;
- `ISecretStore`/`EnvironmentSecretStore` como fronteira inicial para
  segredos de configuração;
- testes de round-trip, tamper/AAD, rotação, fallback e conteúdo de cache;
- runbook e checklist de ativação em produção.

## Não reivindicado

As Fases 2 (KV nomeado `vault_secrets` e API administrativa) e 3 (assinatura
JWT gerenciada pelo vault) continuam no plano. A assinatura OpenIddict ainda
usa o certificado configurado pelo STS.
