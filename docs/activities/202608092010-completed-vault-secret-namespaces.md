# Vault — autorização de named secrets por contexto e namespace

## Entrega

- `vaultsecrets` agora persiste `contextid`, `namespace` e `ownersubject`; a
  unicidade é `(contextid, name)` e a listagem possui índice por
  `(contextid, namespace)`.
- O primeiro segmento do nome normalizado é o namespace. Nomes, contextos e
  namespaces usam uma forma ASCII minúscula única, eliminando aliases de
  collation/case e segmentos ambíguos.
- O AAD de novas escritas inclui nome, namespace e contexto. A compatibilidade
  do AAD antigo é aceita somente no contexto `global`, impedindo mover um
  ciphertext legado para outro contexto.
- A API Management aplica capability, contexto e o claim
  `identity_vault_namespace=<contexto>:<namespace>` em get/put/delete. Listagem
  usa o mesmo conjunto e não revela nomes fora dele.
- `vault-secrets` foi incluído nos recursos por item, portanto operações sem ID
  normalizado falham. O recurso de coleção é separado.
- Break-glass usa claim exclusivo, exige MFA, atravessa contexto/namespace de
  modo explícito e grava `vault_break_glass` no audit log. Claims que concedem
  capability, contexto, namespace ou break-glass foram reservadas na API
  genérica de Claims.
- A migração `20260809230136_AddVaultSecretNamespaces` faz backfill dos registros
  existentes para `global` sem alterar ciphertext/AAD e o SQL MariaDB canônico
  foi regenerado.

## Compatibilidade

- As rotas permanecem em `/api/vault/secrets/{name}`; `contextId` é query
  opcional com default `global`.
- Consumidores internos de `ISecretStore` continuam usando o contexto global.
- O owner original não muda em overwrite; `UpdatedBy` registra o último
  operador.

## Validação

```text
dotnet test src/tests/Sufficit.Identity.Tests.csproj -c Release \
  --filter "FullyQualifiedName~VaultTests|FullyQualifiedName~ManagementApplicationAuthorizationTests|FullyQualifiedName~DatabaseSchemaContractTests"
```

Resultado: 65 testes aprovados, zero warnings. A cobertura inclui listagem
filtrada, nome adivinhado, overwrite/delete cross-context, normalização,
field-swap de AAD e auditoria de break-glass.
