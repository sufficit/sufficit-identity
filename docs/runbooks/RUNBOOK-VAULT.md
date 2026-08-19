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

Em hosts que não recebem segredos por um volume efêmero do supervisor, a
implantação Sufficit mantém o PFX em
`/etc/sufficit/identity/vault-kek.pfx` e define
`Sufficit__Vault__CertificatePath` para esse caminho persistente. O caminho
`/run/secrets/sufficit-vault-kek.pfx` continua válido quando o ambiente fornece
esse volume no boot; em ambos os casos o arquivo deve ser `root:www-data` com
modo `0640` e o mesmo material deve estar presente em todas as réplicas.

### Reemissão para extensão de validade

Quando a política operacional exigir um certificado mais longo sem trocar a
chave RSA que já protege o key-ring, reemita o certificado preservando a mesma
chave privada, valide a descriptografia em um canário e só então distribua o
PFX para as demais réplicas. Mantenha temporariamente o PFX anterior como
`vault-kek.previous.pfx`, com `root:www-data:0640`, para rollback. Essa operação
estende a validade do certificado, mas não reduz o impacto de um vazamento da
chave privada; comprometimento exige uma rotação de chave com migração explícita
do Data Protection/Vault.

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
| `distributed-cache/connection-string` | `SUFFICIT_SECRET_DISTRIBUTED_CACHE_CONNECTION_STRING` | `ConnectionStrings:Redis` |
| `identity/certificates/signing-password` | `SUFFICIT_SECRET_IDENTITY_CERTIFICATES_SIGNING_PASSWORD` | `Sufficit:Identity:Certificates:SigningPassword` |
| `identity/certificates/encryption-password` | `SUFFICIT_SECRET_IDENTITY_CERTIFICATES_ENCRYPTION_PASSWORD` | `Sufficit:Identity:Certificates:EncryptionPassword` |
| `vault/kek-certificate-password` | `SUFFICIT_SECRET_VAULT_KEK_CERTIFICATE_PASSWORD` | `Sufficit:Vault:CertificatePassword` |
| `identity/human-verification/secret-key` | `SUFFICIT_SECRET_IDENTITY_HUMAN_VERIFICATION_SECRET_KEY` | `Sufficit:Identity:HumanVerification:SecretKey` |
| `identity/dcr/initial-access-token` | `SUFFICIT_SECRET_IDENTITY_DCR_INITIAL_ACCESS_TOKEN` | `Sufficit:Identity:Mcp:Dcr:InitialAccessToken` |
| `identity/external-providers/{google,github,facebook}/client-id` | `SUFFICIT_SECRET_IDENTITY_EXTERNAL_PROVIDERS_*_CLIENT_ID` | credencial pública do provedor |
| `identity/external-providers/{google,github,facebook}/client-secret` | `SUFFICIT_SECRET_IDENTITY_EXTERNAL_PROVIDERS_*_CLIENT_SECRET` | credencial do provedor |
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
restritas. O JSON não é mais aceito como fallback: o startup rejeita qualquer
valor não vazio em uma chave de segredo conhecida antes de aplicar os overrides
do ambiente. Isso evita que uma credencial reapareça em `appsettings.*.json`
durante um rolling deploy. O verificador de cada host deve ser executado antes
da ativação e nunca imprime valores.

O boundary é deliberadamente síncrono no startup: `Program.cs` cria o
`EnvironmentSecretStore` antes do bind das opções e o STS usa a mesma instância
para resolver `database/connection-string`, senhas dos certificados, credenciais
OAuth e senhas dos transportes SMTP/RabbitMQ. O `VaultBackedSecretStore` não é usado nessa fase, porque o
banco ainda precisa ser aberto para que ele próprio possa ler segredos.

Se o vault estiver desabilitado fora de Development, o processo falha no
startup mesmo que uma configuração legada defina
`RequireEncryptionInProduction=false`. Isso evita downgrade silencioso.

### Snapshot de leitura e Redis

As leituras recorrentes de vaultkeys e vaultsecrets passam por
VaultSnapshotCache. O processo mantém em memória:

- a versão ativa das chaves simétricas e o material embrulhado;
- os JWKs públicos e o material de assinatura embrulhado, inclusive quando o
  Vault gerencia o ciclo de vida das chaves de emissão;
- ciphertext, AAD e metadados dos segredos nomeados.

O valor puro do segredo nunca é colocado no snapshot. A descriptografia ocorre
somente depois que o registro foi localizado e autorizado. Em caso de miss, o
cache tenta primeiro o IDistributedCache e só então consulta o banco. O
serviço de background atualiza as entradas já utilizadas, mantendo o caminho de
requisição em memória durante operação normal.

Para o cluster de produção Apps, configure
`SUFFICIT_SECRET_DISTRIBUTED_CACHE_CONNECTION_STRING` com os três endpoints
Redis privados da VPN (`172.19.1.113`, `172.19.2.101` e `172.19.3.101`) e
mantenha `Sufficit:Identity:DistributedCache:RequireShared=true`. Esse Redis é
dedicado ao Identity; não use o cluster Redis da infraestrutura VoIP.
O host registra AddStackExchangeRedisCache antes do STS; sem essa variável, o
fallback é MemoryDistributedCache, adequado somente para uma réplica.

Quando `Sufficit:Vault:ManageSigningKeys=true`, o banco continua sendo a fonte
de verdade, mas o caminho normal usa o snapshot. As mutações de segredo,
rotação e revogação invalidam o snapshot local, removem a entrada distribuída
e publicam uma invalidação no Redis Pub/Sub. Com Redis ativo, as outras réplicas
removem a entrada em memória imediatamente; sem Redis, a convergência ocorre
pelo refresh/TTL configurado. Alterações diretas nas tabelas não publicam esse
evento e devem ser seguidas de invalidação/restart controlado.

Configuração recomendada:

```json
"Snapshot": {
  "Enabled": true,
  "LocalLifetimeSeconds": 10,
  "DistributedLifetimeSeconds": 30,
  "RefreshIntervalSeconds": 10,
  "MaxEntries": 4096
}
```

O snapshot é uma otimização de leitura, não uma fonte de verdade: falhas do
Redis são tratadas como miss e retornam ao banco; falhas do banco não servem
uma entrada expirada.

O Redis Apps é um cluster de três masters, sem réplicas de dados, destinado
exclusivamente a cache e invalidação. Os slots são distribuídos entre os
masters e o cluster usa `cluster-require-full-coverage no`; a perda de um nó
não deve ser tratada como perda de dados persistentes, mas as chaves nos slots
desse nó podem ficar indisponíveis até a recuperação. Para dados que exigem
durabilidade ou redundância de leitura, use o banco de dados, não o snapshot.

## Rotação

`IKeyVault.RotateKeyAsync("nome-da-chave")` cria uma nova versão. Novas
gravações usam a versão mais alta e blobs antigos continuam decifráveis porque
o ciphertext é auto-descritivo (`v1.<nome>:<versão>...`). A rotação não exige
reescrita imediata dos dados. O cache de chaves em memória é descartado no
reinício; as versões persistidas são desembrulhadas novamente pela KEK
configurada.

Monitore `sufficit.vault.aes_gcm.encryptions` por `key.name` e `key.version`.
O orçamento default é 250 milhões de mensagens por versão e pode ser ajustado
em `AesGcmMessageBudgetPerKeyVersion`; agregue todas as réplicas e reinícios no
backend de métricas. Ao atingir 80%, planeje `RotateKeyAsync`. Ao atingir o
orçamento, interrompa novas gravações para esse key name ou rotacione antes de
retomar. A rotação automática por contagem permanece desabilitada até existir
volume operacional suficiente para definir uma política sem oscilações.

Antes de remover uma versão antiga, confirme que não existem valores com essa
versão e mantenha um backup testado do banco e do key-ring.

### Chaves de assinatura

Esta seção se aplica somente quando
`Sufficit:Vault:ManageSigningKeys=true`. No modo atual, com essa opção
desligada, o STS continua assinando tokens com o PFX configurado e a tabela
`vaultkeys` não participa da emissão nem da revogação desses tokens.

`RotateSigningKeyAsync(nome, operationId, reason)` é idempotente e protegido por
lease distribuído em `vaultsigningkeylocks`. A nova versão entra em `Active`; a
anterior passa a `Retiring`, deixa de emitir imediatamente e continua no JWKS
até `SigningKeyOverlapSeconds`. O STS recusa uma janela menor que a maior vida
útil configurada de access, identity ou refresh token. O serviço de lifecycle
grava `RetiredAtUtc` ao fim da janela e mantém um journal sem segredos em
`vaultsigningkeyoperations`.

Em comprometimento, `RevokeSigningKeyAsync` exige `operationId` e motivo. A
versão vai para `Revoked`, sai do JWKS e deixa de assinar ou verificar após a
invalidação do snapshot. Com Redis Pub/Sub, essa propagação é imediata entre as
réplicas conectadas; sem Redis, vale o refresh/TTL. Se a versão revogada era a
ativa, emissão fica indisponível até uma rotação deliberada criar a substituta.
Registre esse impacto na resposta ao incidente antes da revogação, quando o
risco permitir.

Para um segredo nomeado, use a API de gestão com uma capability de leitura ou
gestão. O `PUT /api/vault/secrets/{name}?contextId=<contexto>` recebe
`{ "value": "..." }`; `GET` retorna apenas nome, namespace, contexto, owner,
data, operador e `hasValue`. O valor só pode ser lido por consumidores internos
através de `IVaultNamedSecretStore`.

O primeiro segmento do nome é o namespace e todos os segmentos filhos o
herdam; por exemplo, `providers/google/client-secret` pertence a `providers`.
Nomes e contextos são normalizados para ASCII minúsculo antes da autorização e
persistência. O operador precisa, simultaneamente, da capability, da associação
confiável `identity:tenant` e de um claim `identity_vault_namespace` no formato
`<contextId>:<namespace>` (por exemplo `global:providers`). Listagens são
filtradas para exatamente esses pares; capability global não revela os demais
nomes.

O claim `identity_vault_break_glass=identity.vault.secrets` é separado dos
grants comuns, exige MFA e cada leitura/mutação registra
`ReasonCode=vault_break_glass`. Os tipos de claim de tenant, namespace,
capability e break-glass são reservados pela API genérica de Claims e não podem
ser atribuídos por ela. O break-glass pode ultrapassar a restrição de namespace,
mas nunca a associação ao tenant. A emissão desses claims pertence ao processo
externo de acesso privilegiado.

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

## Consumo remoto (consolidação 2026-08)

O vault do Identity é o cofre central da Sufficit. O `sufficit-ai` retirou o
vault próprio (`arin_secrets` + Data Protection) e consome este via REST.

Superfície para consumidores remotos:

- `GET /api/vault/secrets/resolve?name=<nome>&contextId=<ctx>` — devolve o
  valor em claro. `404` = inexistente; `410 Gone` = expirado (o valor nunca é
  devolvido depois da expiração). Exige a capability dedicada
  `identity.vault.secrets.resolve` (separada de `read`/`manage` de propósito:
  metadados ≠ texto claro). Toda resolução — inclusive a recusa por expiração —
  é registrada na auditoria de management.
- `PUT /api/vault/secrets/{nome}` agora aceita `expiresAtUtc` opcional; o
  status (`Active`/`ExpiringSoon` janela de 7 dias/`Expired`) aparece nos
  metadados de `GET`/listagem. Expiração no passado é rejeitada.
- Pacote cliente: `Sufficit.Identity.Vault.Client` (`IVaultSecretsClient`) —
  REST fino, sem material de chave, com cache de resolução (TTL curto) e
  fallback stale limitado quando o Identity está indisponível. O host anexa o
  próprio handler de client-credentials ao `IHttpClientBuilder` retornado por
  `AddSufficitVaultSecretsClient`.

Para autorizar um serviço (ex.: `SufficitAIServer`): conceda o scope
`identity.management` e mapeie o `client_id` exato em
`Management:Authorization:ServiceClientCapabilities` com as capabilities de
vault necessárias (`identity.vault.secrets.read`, `.manage`, `.resolve`). O
resolver também aceita `sub`/`azp` equivalentes do token, mas nunca transforma
o escopo OAuth em capability. Atenção ao `RequireMfa` do management: principais
de serviço não carregam `amr`, então a implantação precisa de política
compatível para esses clientes.

Os segredos do sufficit-ai vivem no namespace `ai/` (nome = `ai/<referência>`).
Contextos usados pelo AI: `<guid>` do tenant para segredos compartilhados no
tenant, e `user-<guid>` para segredos pessoais (contexto nulo/vazio no AI
significa "somente do usuário proprietário" — não existe tier global
compartilhado). A cópia one-shot roda no sufficit-ai com
`Sufficit:AI:Vault:MigrateLegacySecrets=true`; linhas globais legadas migram
para o contexto pessoal do dono, e as sem dono para `legacy-unassigned`
(reatribuir manualmente). A tabela legada `arin_secrets` só é removida
manualmente após a validação.
