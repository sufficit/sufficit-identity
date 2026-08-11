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

## Rollout de produção — 2026-08-11

- `SUFFICIT_SECRET_DISTRIBUTED_CACHE_CONNECTION_STRING` foi instalado fora do
  release, em `/etc/sufficit/identity/vault-secrets.env`, nos três nós
  `eveo-apps`, `apoint-apps` e `castrum-apps`, mantendo `root:www-data` e modo
  `0640`.
- A conexão aponta para o endpoint Redis privado do cluster; a senha não é
  versionada, registrada em log ou incluída nesta atividade.
- O release `2911dadb2679ef63c016f6d5b83e158ddce2b124` foi reativado de forma
  coordenada. Todos os nós passaram no gate de revisão, saúde, readiness,
  certificado e JWKS.
- Os três serviços confirmaram no log a assinatura Redis Pub/Sub ativa. O
  snapshot continua usando memória local como caminho quente, Redis como
  compartilhamento/invalidação e banco somente em miss/expiração.

### Redis dedicado do cluster Apps

- O cluster VoIP não é usado pelo Identity. Foi criado um cluster Redis
  dedicado nos próprios hosts Apps, usando somente a VPN `suffvpn`:
  `172.19.1.113` (apoint), `172.19.2.101` (eveo) e `172.19.3.101` (castrum).
- Cada host é um master Redis 7.0.15; os `16384` slots foram distribuídos
  entre os três masters, com AOF `everysec`, limite de `1gb` e política
  `allkeys-lru`. As portas 6379/16379 não ficam expostas no endereço público.
- A conexão dos três Identity usa os três endpoints VPN. A senha permanece
  somente nos arquivos de segredo do host e não é versionada.
- O teste de chave com roteamento de cluster e o teste Pub/Sub entre masters
  passaram. Como esse Redis serve apenas cache/invalidação, não há réplicas de
  dados; a fonte de verdade continua sendo o banco e o snapshot tolera a perda
  temporária de um master por TTL/miss.

### Recuperação do nó Redis `apoint-voip`

- O CT 1104 estava em `emergency.target`: as interfaces de rede estavam
  `DOWN` e o `redis-server` não havia iniciado porque três mounts GCS falhos
  bloqueavam a transação de boot.
- As interfaces foram reativadas, o Redis foi iniciado preservando AOF/RDB e
  os mounts GCS receberam `nofail,_netdev`, evitando que uma indisponibilidade
  de armazenamento impeça a rede e o Redis de subirem.
- Após o reboot do CT, o nó voltou a `master,connected`; o cluster ficou com
  `cluster_state:ok`, todos os `16384` slots atribuídos e sem `pfail/fail`.
