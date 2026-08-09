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
protegido pela autoridade KEK configurada (`dataprotection`, `certificate` ou
`external`). Em produção, o key-ring do Data Protection usa um certificado
dedicado ao vault e diferente de todos os certificados de assinatura. O texto
puro não é retornado ao banco/cache depois de gravado.

## Ativação

Comece em uma implantação de canário:

```json
{
  "Sufficit": {
    "Vault": {
      "Enabled": true,
      "KeySource": "dataprotection",
      "DataProtectionPurpose": "Sufficit.Identity.Vault.Master.v1",
      "CertificatePath": "/run/secrets/sufficit-vault-kek.pfx",
      "CertificatePassword": "",
      "SigningKeyOverlapSeconds": 1209600,
      "SigningKeyLockSeconds": 60
    }
  }
}
```

O mesmo bloco pode ser fornecido por variáveis (`Sufficit__Vault__Enabled=true`).
A senha do PFX deve vir de
`SUFFICIT_SECRET_VAULT_KEK_CERTIFICATE_PASSWORD`. O key-ring do Data Protection
continua compartilhado entre réplicas, mas novas chaves do ring são protegidas
pelo certificado dedicado acima, nunca pelo certificado de assinatura. Não
altere `DataProtectionPurpose` depois de haver dados cifrados.

`KeySource=dataprotection` é o caminho compatível para ambientes que já têm
DEKs embrulhadas por Data Protection. `KeySource=certificate` usa o mesmo PFX
dedicado para embrulhar DEKs diretamente. `KeySource=external` exige uma
implementação registrada de `IVaultExternalKeyEncryptionProvider` e um
`ExternalKeyIdentifier` imutável que fixe a versão da chave KMS/HSM. O startup
faz um round-trip de wrap/unwrap e falha se a KEK não estiver utilizável.

Em produção, recomenda-se a sequência:

1. confirmar backup restaurável do banco, do key-ring compartilhado e dos
   certificados antigos, sem copiar material privado para a evidência;
2. configurar `Enabled=true` em todas as réplicas antes de implantar esta
   versão; o processo recusa startup com vault desabilitado fora de
   Development;
3. iniciar por uma réplica de canário e observar os avisos de leitura `pt1.`;
4. migrar/regravar registros que ainda tenham o marcador `pt1.`;
5. validar zero leituras legadas por uma janela completa e manter a versão
   anterior somente pelo período de rollback acordado.

Para separar um key-ring antigo ainda protegido pelo certificado de assinatura,
configure temporariamente `LegacyDataProtectionCertificateMigration` com
`Owner`, `Reason` e `ExpiresAtUtc`. Durante essa janela, os certificados de
assinatura anteriores são somente decrypt-only; toda chave DP nova é protegida
pelo PFX dedicado. A janela não pode exceder 180 dias. Depois de confirmar que
o ring antigo expirou/rotacionou, remova o bloco e reinicie uma réplica de
canário; qualquer dependência residual falhará fechada no canário.

`RequireEncryptionInProduction` permanece no binding para compatibilidade, mas
seu valor não desliga o guard. O default é `true` e `PassThroughKeyVault` é
restrito a Development.

### Segredos de configuração no ambiente

O host aplica variáveis `SUFFICIT_SECRET_*` antes de vincular as opções de
startup. Elas têm precedência sobre JSON e os consumidores de banco, certificados
e provedores externos consultam o `ISecretStore` por nome lógico. Isso permite
retirar credenciais de `appsettings.*.json` sem acoplar os consumidores ao
provedor de configuração:

| Nome lógico | Variável | Chave substituída |
|---|---|---|
| `database/connection-string` | `SUFFICIT_SECRET_DATABASE_CONNECTION_STRING` | `ConnectionStrings:DefaultConnection` |
| `identity/certificates/signing-password` | `SUFFICIT_SECRET_IDENTITY_CERTIFICATES_SIGNING_PASSWORD` | `Sufficit:Identity:Certificates:SigningPassword` |
| `identity/certificates/encryption-password` | `SUFFICIT_SECRET_IDENTITY_CERTIFICATES_ENCRYPTION_PASSWORD` | `Sufficit:Identity:Certificates:EncryptionPassword` |
| `vault/kek-certificate-password` | `SUFFICIT_SECRET_VAULT_KEK_CERTIFICATE_PASSWORD` | `Sufficit:Vault:CertificatePassword` |
| `identity/human-verification/secret-key` | `SUFFICIT_SECRET_IDENTITY_HUMAN_VERIFICATION_SECRET_KEY` | `Sufficit:Identity:HumanVerification:SecretKey` |
| `identity/external-providers/{google,github,facebook}/client-secret` | `SUFFICIT_SECRET_IDENTITY_EXTERNAL_PROVIDERS_*` | credencial do provedor |
| `identity/smtp/password` | `SUFFICIT_SECRET_IDENTITY_SMTP_PASSWORD` | `Sufficit:Identity:Smtp:Password` |
| `exchange/rabbitmq/password` | `SUFFICIT_SECRET_EXCHANGE_RABBITMQ_PASSWORD` | `Sufficit:Exchange:RabbitMQ:Password` |

O instalador cria o arquivo opcional
`/etc/sufficit/identity/vault-secrets.env` a partir de
`helpers/vault-secrets.env.template` e não sobrescreve um arquivo já existente.
O unit do systemd carrega esse arquivo antes do processo, mantendo os valores
fora do release. Preencha-o pelo gerenciador de segredos do host, sem editar o
template versionado, e valide somente nomes, valores não vazios e permissões
com:

```bash
sudo /usr/libexec/sufficit-identity/check-vault-secrets.sh \
  /etc/sufficit/identity/vault-secrets.env
```

O verificador nunca imprime valores. Em hosts onde o helper ainda não foi
instalado, execute `helpers/check-vault-secrets.sh` a partir do release. Depois
de qualquer alteração, use `systemctl daemon-reload` e reinicie apenas a
instância validada. O arquivo precisa ser `root:www-data` com modo `0640`.

As variáveis devem ser instaladas pelo supervisor/secret manager com permissões
restritas. O JSON ainda é aceito como fallback de rolling deploy; depois de
validar que cada override está presente em todas as réplicas, remova o valor
legado e registre apenas a evidência redigida de rotação. O fallback em
`ISecretStore` preserva a compatibilidade sem registrar o valor, permitindo
medir quando a dependência de configuração plaintext chegou a zero.

O boundary é deliberadamente síncrono no startup: `Program.cs` cria o
`EnvironmentSecretStore` antes do bind das opções e o STS usa a mesma instância
para resolver `database/connection-string`, senhas dos certificados, credenciais
OAuth e senhas dos transportes SMTP/RabbitMQ. O `VaultBackedSecretStore` não é usado nessa fase, porque o
banco ainda precisa ser aberto para que ele próprio possa ler segredos.

Se o vault estiver desabilitado fora de Development, o processo falha no
startup mesmo que uma configuração legada defina
`RequireEncryptionInProduction=false`. Isso evita downgrade silencioso.

## Rotação

`IKeyVault.RotateKeyAsync("nome-da-chave")` cria uma nova versão. Novas
gravações usam a versão mais alta e blobs antigos continuam decifráveis porque
o ciphertext é auto-descritivo (`v1.<nome>:<versão>...`). A rotação não exige
reescrita imediata dos dados. O cache de chaves em memória é descartado no
reinício; as versões persistidas são desembrulhadas novamente pela KEK
configurada.

Antes de remover uma versão antiga, confirme que não existem valores com essa
versão e mantenha um backup testado do banco e do key-ring.

### Chaves de assinatura

`RotateSigningKeyAsync(nome, operationId, reason)` é idempotente e protegido por
lease distribuído em `vaultsigningkeylocks`. A nova versão entra em `Active`; a
anterior passa a `Retiring`, deixa de emitir imediatamente e continua no JWKS
até `SigningKeyOverlapSeconds`. O STS recusa uma janela menor que a maior vida
útil configurada de access, identity ou refresh token. O serviço de lifecycle
grava `RetiredAtUtc` ao fim da janela e mantém um journal sem segredos em
`vaultsigningkeyoperations`.

Em comprometimento, `RevokeSigningKeyAsync` exige `operationId` e motivo. A
versão vai para `Revoked`, sai imediatamente do JWKS e deixa de assinar ou
verificar; tokens ainda dentro do TTL que usem esse `kid` também deixam de ser
aceitos. Se a versão revogada era a ativa, emissão fica indisponível até uma
rotação deliberada criar a substituta. Registre esse impacto na resposta ao
incidente antes da revogação, quando o risco permitir.

Para um segredo nomeado, use a API de gestão com uma capability de leitura ou
gestão. O `PUT /api/vault/secrets/{name}?contextId=<contexto>` recebe
`{ "value": "..." }`; `GET` retorna apenas nome, namespace, contexto, owner,
data, operador e `hasValue`. O valor só pode ser lido por consumidores internos
através de `IVaultNamedSecretStore`.

O primeiro segmento do nome é o namespace e todos os segmentos filhos o
herdam; por exemplo, `providers/google/client-secret` pertence a `providers`.
Nomes e contextos são normalizados para ASCII minúsculo antes da autorização e
persistência. O operador precisa, simultaneamente, da capability, do claim de
contexto configurado e de um claim `identity_vault_namespace` no formato
`<contextId>:<namespace>` (por exemplo `global:providers`). Listagens são
filtradas para exatamente esses pares; capability global não revela os demais
nomes.

O claim `identity_vault_break_glass=identity.vault.secrets` é separado dos
grants comuns, exige MFA e cada leitura/mutação registra
`ReasonCode=vault_break_glass`. Os tipos de claim de contexto, namespace,
capability e break-glass são reservados pela API genérica de Claims e não podem
ser atribuídos por ela. A emissão desses claims pertence ao processo externo de
acesso privilegiado.

## Compatibilidade e diagnóstico

- `pt1.` é o marcador de compatibilidade sem criptografia. Ele é aceito apenas
  durante a migração e gera aviso no log do vault.
- Referências de client secret em texto cru são aceitas somente pelo backend
  pass-through de Development. Com o vault real, formato inválido falha fechado.
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
publica somente a versão ativa e versões ainda em sobreposição. Com a opção
desligada, o caminho existente por certificado permanece autoritativo. O
adapter KMS/HSM é intencionalmente agnóstico de fornecedor: cada implantação
deve registrar `IVaultExternalKeyEncryptionProvider` para seu serviço remoto.

Para habilitar a assinatura delegada, aplique primeiro
`20260809224037_AddVaultSigningKeyLifecycle`, defina `SigningKeyName` (padrão
`oidc-signing`) e valide uma rotação idempotente no canário. O private key nunca
é incluído no objeto `SecurityKey` nem no JWKS; ele é desembrulhado somente
durante a operação de assinatura.

Limitação atual: a implantação ainda deve fornecer o PFX de signing separado quando
`ManageSigningKeys=true`, porque os geradores auxiliares (logout/JARM/SSF/CIBA)
continuam usando esse certificado.
O provider do vault é a fonte de assinatura dos tokens OpenIddict; a migração
dessas superfícies auxiliares para o vault é uma etapa posterior.
