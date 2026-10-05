# Credencial delegada de dispositivo (troca RFC 8693 presa a DPoP)

Fase 5 de `sufficit-ai-genius/docs/PLAN-REMOTE-SESSIONS-KUBERNETES.md`
("especificação aprovada (2026-10-04)"). Um cliente de primeira parte já
logado (o Genius local) troca o access token do usuário por uma credencial
**de outro cliente** (o executor), presa à chave DPoP que o dispositivo gerou
e nunca entrega. Quem transporta a credencial (o Run) não consegue usá-la.

O recurso é genérico do produto: "credencial delegada de dispositivo". Nada no
código cita Genius, Run ou executor; tudo vem da configuração. Desligado por
padrão.

Ponto de partida: `main` em `14772f5`, que registrou o cliente
`sufficit-ai-genius-executor` e o escopo `genius.executor.delegate` em
produção, inertes ([atividade anterior](202610042110-genius-executor-client.md)).

## Contrato

`POST /connect/token`, `grant_type=urn:ietf:params:oauth:grant-type:token-exchange`:

| Parâmetro | Valor |
|---|---|
| `client_id`/autenticação | cliente delegante (lista `DelegatorClientIds`), com `gt:token-exchange` |
| `subject_token` / `subject_token_type` | access token do usuário emitido ao próprio delegante / `...:access_token` |
| `requested_token_type` | `urn:ietf:params:oauth:token-type:refresh_token` |
| `audience` | `DelegateClientId` |
| `dpop_jkt` | thumbprint RFC 7638 (SHA-256, base64url canônico, 43 caracteres) da chave do dispositivo |
| `executor_id` | UUID do dispositivo (rótulo e chave de substituição) |

Resposta (RFC 8693 §2.2.1): o refresh token do cliente delegado vem em
`access_token`, com `issued_token_type=urn:ietf:params:oauth:token-type:refresh_token`,
`token_type=N_A` e `expires_in` até o prazo absoluto. **Não há access token na
resposta da troca**: o dispositivo resgata a credencial com `grant_type=refresh_token`,
`client_id=<delegado>` e prova DPoP da chave presa, e recebe access token
`DPoP` com `cnf.jkt` e novo refresh token. Diferença deliberada em relação ao
texto do plano ("refresh_token e access_token"): o OpenIddict emite um único
token na troca, e assim o delegante nunca segura um access token do delegado.

## Regras aplicadas (em `DelegatedCredentialIssuer`)

1. chamador na lista `DelegatorClientIds` (lista vazia = ninguém delega);
2. sem `actor_token`;
3. `subject_token` é access token, emitido **somente** ao chamador (parte autorizada única);
4. sujeito é usuário existente que ainda passa em `CanSignInAsync`;
5. `subject_token` contém `RequiredScope`;
6. `auth_time` presente e no máximo `MaxAuthAgeHours` atrás (sem `auth_time` = recusa);
7. `dpop_jkt` válido; `executor_id` UUID;
8. `may_act` e profundidade da cadeia `act` respeitados, como na troca comum;
9. cliente delegado registrado com `gt:refresh_token`;
10. teto `MaxActivePerUser` de credenciais ativas, sem contar a do mesmo `executor_id`
    (mesmo rótulo de novo **revoga** a anterior — autorização e tokens).

Escopos emitidos: permissões `scp:` do delegado ∩ escopos do `subject_token`
(∩ `scope` pedido, se houver), nunca o `RequiredScope`, mais `offline_access`
(sem ele o OpenIddict não gira o refresh token). Escopo que o delegado não
tem — `identity.mcp`, gerenciamento — não passa.

A emissão cria uma autorização OpenIddict ad-hoc do usuário para o cliente
**delegado**, com a propriedade `delegated_credential`
(`{label, delegator, expires_at}`); o token fica registrado sob o cliente
delegado (`AttachDelegatedCredentialApplication`). `act` = `{sub: <delegante>}`,
aninhando a cadeia anterior, e persiste em cada refresh.

Prazo absoluto: `CredentialLifetimeDays`. `ClampDelegatedCredentialLifetime`
corta a validade de todo refresh/access token da credencial no prazo, então
renovar não estende; só uma nova delegação (o Genius do dono) renova.

## Auditoria e aviso

Toda emissão e toda recusa geram uma linha em `ManagementAuditEvents`
(capability `token_exchange.delegated_credential`, outcome `issued`/`refused`,
`ReasonCode` com a regra que recusou). O JSON registra delegante, delegado,
rótulo, escopos e prazo, nunca token, thumbprint ou conteúdo do token de
origem. Se a linha de auditoria da emissão não puder ser gravada, a credencial
é revogada e a troca responde `temporarily_unavailable` (fail closed).

`NotifyOnIssue=true` envia e-mail ao endereço confirmado do usuário pelo
`IEmailSender` existente (textos em `AccountMessages`, pt-BR e en). Falha de
entrega só é logada.

## Autoatendimento

`/manage/grants` ganhou a seção "Credenciais de dispositivos": rótulo
(`executor_id`), quem autorizou, emissão, expiração e botão de revogar
(`IAccountAccessService.GetDelegatedCredentialsAsync` /
`RevokeDelegatedCredentialAsync`, com métodos padrão na interface para não
quebrar implementações externas). A revogação derruba autorização e tokens.
Revogar o aplicativo delegado em "Aplicações conectadas", trocar senha ou
"encerrar todas as sessões" também derruba todas as credenciais.

## Postura de produção

`StsProductionPostureContributor.EvaluateDelegatedCredentials`, só com o recurso ligado:

| Finding | Severidade |
|---|---|
| `delegated-credentials-no-delegators` | advisory |
| `delegated-credentials-long-lifetime` (> 90 dias) | **bloqueante** |
| `delegated-credentials-stale-sign-in` (`MaxAuthAgeHours` > 24) | advisory |
| `delegated-credentials-silent` (`NotifyOnIssue=false`) | advisory |

Ligar o recurso sem `Dpop:Enabled=true`, ou com `DelegateClientId`/`RequiredScope`
vazios ou limites fora da faixa, impede a inicialização.

## Configuração para ligar em produção

Valores iniciais por decisão do dono (04/10/2026): **ajustáveis pela
configuração depois da prática**; nenhum está fixo no código.

```json
"Sufficit": { "Identity": {
  "Dpop": { "Enabled": true },
  "TokenExchange": {
    "DelegatedCredentials": {
      "Enabled": true,
      "DelegatorClientIds": [ "sufficit-ai-genius" ],
      "DelegateClientId": "sufficit-ai-genius-executor",
      "RequiredScope": "genius.executor.delegate",
      "MaxAuthAgeHours": 12,
      "CredentialLifetimeDays": 30,
      "MaxActivePerUser": 10,
      "NotifyOnIssue": true
    }
  }
} }
```

Se `TokenExchange:AllowedClientIds` estiver configurado, `sufficit-ai-genius`
também precisa constar nele. Ordem: deploy do código → configuração acima nos
três nós (operação de configuração separada) → **só então** conceder
`gt:token-exchange` e `scp:genius.executor.delegate` ao cliente
`sufficit-ai-genius`, e o Genius pedir `genius.executor.delegate` no login.

## Validação

- `DelegatedCredentialTests`: 21 casos — sucesso com a chave certa, recusa com
  chave errada/sem prova/pelo delegante, `act`/`cnf.jkt`/escopos no access
  token, prazo absoluto após refresh, mesmo rótulo revoga o anterior, teto e
  substituição no teto, cada recusa com erro e `ReasonCode`, pedido fora do
  contrato, recurso desligado = comportamento antigo, listagem e revogação
  pelo usuário, `IsRecent`, thumbprint canônico, postura e validação de
  configuração.
- Suítes existentes intactas (ver contagem no commit).

## Pendências

- Concorrência: pedidos simultâneos do mesmo usuário podem ultrapassar o teto
  pelo número de corridas; o teto limita acúmulo, não é trava.
- O rótulo exibido ao usuário é o UUID; nome amigável do ambiente exigiria um
  parâmetro novo no contrato.
- Revogação no retire/purge do executor (Run) e no "remover sessão" do Genius
  é do lado deles: chamar `/connect/revocation` com o refresh token, ou o
  autoatendimento.
