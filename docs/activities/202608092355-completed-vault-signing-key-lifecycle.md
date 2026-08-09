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
- Há três backends de KEK: Data Protection com key-ring protegido por PFX
  dedicado, wrapping RSA direto por certificado e adapter KMS/HSM externo com
  identificador de versão fixado. O mesmo thumbprint/caminho dos certificados
  de assinatura é recusado.
- A transição de key-rings DP antes protegidos pelo certificado de assinatura
  usa uma exceção decrypt-only com owner, motivo, expiração e limite de 180
  dias; novas chaves são sempre protegidas pelo certificado dedicado.

## Operação

- Mantenha `Sufficit:Vault:ManageSigningKeys=true` somente com o Vault
  habilitado e configure `SigningKeyOverlapSeconds` para cobrir a maior vida
  útil de access, refresh e identity token.
- Para uma rotação segura, envie um `operationId` estável e um motivo. Em caso
  de comprometimento, revogue o `keyVersion` com motivo obrigatório; a
  revogação não espera a janela de sobreposição.
- Em `dataprotection`, forneça o PFX dedicado para proteger o key-ring e use a
  janela legada somente durante a rotação. Em `external`, registre
  `IVaultExternalKeyEncryptionProvider` e fixe `ExternalKeyIdentifier`.

## Validação

```text
dotnet restore Sufficit.Identity.sln --locked-mode
dotnet test src/tests/Sufficit.Identity.Tests.csproj --no-restore --filter FullyQualifiedName~VaultTests
dotnet test src/tests/Sufficit.Identity.Tests.csproj --no-restore --filter FullyQualifiedName~DatabaseSchemaContractTests
```

Os testes cobrem a rotação idempotente, concorrência entre réplicas, recuperação
de lease, sobreposição, aposentadoria, revogação imediata, perda de KEK,
rollback, certificado dedicado, adapter externo e contrato do schema. A
validação focada final executou 39 testes sem warning.
