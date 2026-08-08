# Runbook — vault interno e segredos em repouso

## Escopo atual

O módulo `Sufficit.Identity.Vault` fornece envelope encryption AES-256-GCM,
versionamento de chaves e uma fronteira de resolução de segredos. Na Fase 1,
os seguintes valores passam pelo vault quando ele está habilitado:

- `SsfStream.Authorization` (AAD `stream_id`);
- payloads do `DistributedDpopNonceStore` (AAD com escopo e partição);
- payloads do `DistributedCibaPendingRequestStore` (AAD com escopo e
  `auth_req_id`).
- segredos nomeados em `vaultsecrets` (AAD com o nome lógico); a API de gestão
  aceita escrita, mas nunca devolve o valor.

As chaves de item ficam em `vaultkeys`; o material armazenado no banco é
sempre protegido pelo Data Protection configurado pelo STS. O texto puro não
é retornado ao banco/cache depois de gravado.

## Ativação

Comece em uma implantação de canário:

```json
{
  "Sufficit": {
    "Vault": {
      "Enabled": true,
      "KeySource": "dataprotection",
      "DataProtectionPurpose": "Sufficit.Identity.Vault.Master.v1"
    }
  }
}
```

O mesmo bloco pode ser fornecido por variáveis (`Sufficit__Vault__Enabled=true`).
O key-ring do Data Protection precisa ser compartilhado entre réplicas e
protegido pela estratégia de certificado já usada pelo STS. Não altere
`DataProtectionPurpose` depois de haver dados cifrados.

Em produção, recomenda-se a sequência:

1. implantar os leitores compatíveis (a versão atual entende `pt1.` e valores
   legados);
2. habilitar `Enabled=true` em uma réplica e observar os logs;
3. migrar/regravar registros que ainda tenham o marcador `pt1.`;
4. habilitar em todas as réplicas;
5. somente quando não houver leituras legadas, definir
   `RequireEncryptionInProduction=true`.

Se `RequireEncryptionInProduction=true` e o vault estiver desabilitado, o
processo falha no startup. Isso evita um downgrade silencioso.

## Rotação

`IKeyVault.RotateKeyAsync("nome-da-chave")` cria uma nova versão. Novas
gravações usam a versão mais alta e blobs antigos continuam decifráveis porque
o ciphertext é auto-descritivo (`v1.<nome>:<versão>...`). A rotação não exige
reescrita imediata dos dados. O cache de chaves em memória é descartado no
reinício; as versões persistidas são desembrulhadas novamente pelo Data
Protection.

Antes de remover uma versão antiga, confirme que não existem valores com essa
versão e mantenha um backup testado do banco e do key-ring.

Para um segredo nomeado, use a API de gestão com uma capability de leitura ou
gestão. O `PUT /api/vault/secrets/{name}` recebe `{ "value": "..." }`; `GET`
retorna apenas nome, data, operador e `hasValue`. O valor só pode ser lido por
consumidores internos através de `IVaultNamedSecretStore`.

## Compatibilidade e diagnóstico

- `pt1.` é o marcador de compatibilidade sem criptografia. Ele é aceito apenas
  durante a migração e gera aviso no log do vault.
- Valores SSF, DPoP e CIBA legados em claro continuam legíveis durante o
  rolling deploy; novas escritas já são cifradas quando `Enabled=true`.
- Erros de AAD, ciphertext truncado ou tag GCM inválida fazem a leitura falhar
  fechada. No CIBA/DPoP o item é tratado como indisponível; no SSF a falha fica
  registrada para não interromper a listagem de todos os streams.
- Não copie ciphertext, key-ring ou valores de ambiente para o repositório.
  O `ISecretStore` padrão lê primeiro `SUFFICIT_SECRET_<NOME>` (caracteres não
  alfanuméricos viram `_`) e só então cai na configuração.

## Limitações conhecidas

O provedor de segredos nomeados e a primitiva de assinatura RSA versionada já
estão disponíveis. Com `Sufficit:Vault:ManageSigningKeys=true` (e o vault
habilitado), o OpenIddict usa o provider delegado ao vault e o endpoint JWKS
publica todas as versões não aposentadas. A rotação mantém as chaves antigas
publicadas para validar tokens em trânsito. Com a opção desligada, o caminho
existente por certificado permanece autoritativo. O backend de KEK externo
(KMS/HSM) também não está conectado por padrão.

Para habilitar a assinatura delegada, aplique primeiro as migrações de
`vault_keys`, defina `SigningKeyName` (padrão `oidc-signing`) e mantenha uma
janela de sobreposição: execute `IKeyVault.RotateSigningKeyAsync`/a operação
administrativa equivalente, confirme os dois `kid`s no JWKS e só aposente a
versão antiga depois do TTL máximo dos tokens. O private key nunca é incluído
no objeto `SecurityKey` nem no JWKS; ele é desembrulhado somente durante a
operação de assinatura.

Limitação atual: a implantação ainda deve fornecer o PFX de signing quando
`ManageSigningKeys=true`, porque os geradores auxiliares (logout/JARM/SSF/CIBA)
e a proteção do key-ring de Data Protection continuam usando esse certificado.
O provider do vault é a fonte de assinatura dos tokens OpenIddict; a migração
dessas superfícies auxiliares para o vault é uma etapa posterior.
