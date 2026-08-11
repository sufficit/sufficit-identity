# Snapshot de Vault com invalidação Redis

**Status:** Implementado e validado; rollout de produção nesta entrega.

## Objetivo

Evitar consultas recorrentes às tabelas `vaultkeys` e `vaultsecrets` sem
colocar segredos em claro na memória ou no Redis.

## Implementação

- `VaultSnapshotCache` usa memória local, `IDistributedCache` e banco somente
  em caso de miss ou entrada expirada.
- O snapshot mantém ciphertext, AAD, metadados e material de chave embrulhado;
  valores descriptografados não são armazenados.
- Chaves simétricas e chaves de assinatura gerenciadas também usam o snapshot.
- `RotateSigningKeyAsync`, `RetireSigningKeysAsync`, `RevokeSigningKeyAsync`,
  rotação simétrica e CRUD de segredos invalidam a entrada alterada.
- Quando Redis está configurado, um canal Pub/Sub propaga a invalidação para
  as outras réplicas. Sem Redis, o refresh/TTL é o limite de convergência.
- Os defaults são 10 segundos para memória local e 30 segundos para o cache
  distribuído; podem ser ajustados em `Sufficit:Vault:Snapshot`.

## Operação

Configure `SUFFICIT_SECRET_DISTRIBUTED_CACHE_CONNECTION_STRING` em
`vault-secrets.env` e mantenha
`Sufficit:Identity:DistributedCache:RequireShared=true` em ambientes com mais
de uma réplica. A conexão Pub/Sub é best effort e não bloqueia o processo; se
Redis estiver indisponível, o snapshot continua protegido pelo TTL/refresh.

Alterações diretas em `vaultkeys` ou `vaultsecrets` não publicam eventos. Use as
APIs de lifecycle/secret store ou invalide/reinicie as réplicas após uma
intervenção manual.

## Validação

- `dotnet restore Sufficit.Identity.sln --locked-mode`
- `dotnet build Sufficit.Identity.sln --no-restore`
- `dotnet test src/tests/Sufficit.Identity.Tests.csproj --no-build`
- `646` testes aprovados e `1` ignorado.
