# Vault — isolamento de segredos e consumidores via ISecretStore

## Entrega

- Segredos nomeados agora carregam `ContextId`, `Namespace` e `OwnerSubject`.
  O índice único passou a ser `(ContextId, Name)` e a listagem aceita apenas
  namespaces autorizados para o contexto solicitado.
- A migration `20260809230136_AddVaultSecretNamespaces` migra registros
  legados para o contexto `global`, deriva o namespace do primeiro segmento do
  nome e preserva o operador de atualização como proprietário inicial.
- A autorização de gestão separa capability de namespace. Claims no formato
  `<contexto>:<namespace>` são exigidas; break-glass exige claim dedicada e
  evidência MFA, registra auditoria e nunca retorna o valor em plaintext.
- A validação de claim reserva os tipos usados pela política de contexto,
  tier, capability, namespace e break-glass contra alterações pela API genérica.
- Consumidores de DCR, verificação humana e certificado KEK resolvem segredos
  pelo `ISecretStore`. Os valores em opções/appsettings permanecem somente como
  fallback temporário para rolling deploys antigos.

## Operação

- Conceda `identity_vault_namespace` com valores como
  `global:providers` ou `tenant-a:billing` junto das capabilities
  `identity.vault.secrets.read/manage`.
- Para emergência, emita `identity_vault_break_glass=identity.vault.secrets`
  com `amr` contendo MFA; cada uso deve ser revisado no audit log.
- Migre os segredos de startup para as variáveis
  `SUFFICIT_SECRET_<NOME_LÓGICO>`. Os nomes relevantes incluem
  `identity/dcr/initial-access-token`,
  `identity/human-verification/secret-key` e
  `vault/kek-certificate-password`.

## Validação

```text
dotnet restore Sufficit.Identity.sln --locked-mode
dotnet build Sufficit.Identity.sln -c Release --no-restore
dotnet test src/tests/Sufficit.Identity.Tests.csproj -c Release --no-restore --filter "FullyQualifiedName~VaultTests|FullyQualifiedName~ManagementApplicationAuthorizationTests|FullyQualifiedName~DatabaseSchemaContractTests"
```
