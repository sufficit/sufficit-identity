# Vault — lifecycle distribuído das chaves de assinatura

## Entrega

- O `IKeyVault` agora suporta rotação idempotente por `operationId`, janela de
  sobreposição configurável, aposentadoria automática e revogação emergencial.
- A rotação usa lease distribuído em `vaultsigningkeylocks` e um journal
  append-only em `vaultsigningkeyoperations`; retries não criam versões extras.
- O JWKS publica apenas chaves ativas ou ainda dentro da sobreposição. Uma
  chave aposentada ou revogada deixa de verificar assinaturas imediatamente.
- O serviço de background executa a aposentadoria em cada réplica, enquanto o
  lease garante que somente uma réplica grava a transição.
- A migração `20260809224037_AddVaultSigningKeyLifecycle` adiciona os campos de
  estado, as tabelas de lease/journal e uma atualização segura dos registros de
  assinatura legados. O script canônico MariaDB foi regenerado.
- O readiness do KEK executa um round-trip de wrap/unwrap na inicialização.
  Nos testes, o schema SQLite é criado antes do `IHostedService`; em produção,
  a falha continua bloqueando o processo.

## Operação

- Mantenha `Sufficit:Vault:ManageSigningKeys=true` somente com o Vault
  habilitado e configure `SigningKeyOverlapSeconds` para cobrir a maior vida
  útil de access, refresh e identity token.
- Para uma rotação segura, envie um `operationId` estável e um motivo. Em caso
  de comprometimento, revogue o `keyVersion` com motivo obrigatório; a
  revogação não espera a janela de sobreposição.
- Use uma fonte de KEK dedicada (certificado separado ou KMS/HSM externo) fora
  de Development. `dataprotection` permanece apenas compatibilidade local.

## Validação

```text
dotnet restore Sufficit.Identity.sln --locked-mode
dotnet test src/tests/Sufficit.Identity.Tests.csproj --no-restore --filter FullyQualifiedName~VaultTests
dotnet test src/tests/Sufficit.Identity.Tests.csproj --no-restore --filter FullyQualifiedName~DatabaseSchemaContractTests
```

Os testes cobrem a rotação idempotente, a sobreposição, a aposentadoria,
revogação imediata e o contrato do schema.
