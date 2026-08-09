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

1. confirmar backup restaurável do banco e do key-ring compartilhado;
2. configurar `Enabled=true` em todas as réplicas antes de implantar esta
   versão; o processo recusa startup com vault desabilitado fora de
   Development;
3. iniciar por uma réplica de canário e observar os avisos de leitura `pt1.`;
4. migrar/regravar registros que ainda tenham o marcador `pt1.`;
5. validar zero leituras legadas por uma janela completa e manter a versão
   anterior somente pelo período de rollback acordado.

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
