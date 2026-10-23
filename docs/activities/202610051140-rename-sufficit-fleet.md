# Renomear `sufficit_fleet` para `sufficit-fleet` (passo 4 feito; 5–6 pendentes)

Decisão do dono (05/10): ids de cliente e audiências com hífen, como
`sufficit-ai-genius`; escopos com ponto (`fleet.api`). `sufficit_fleet` é ao
mesmo tempo o cliente OIDC do Fleet (login + introspecção) e a audiência que o
Fleet confere. OpenIddict não renomeia cliente: cria-se outro e migra-se.

## Ordem (introspecção só responde ao cliente que é audiência do token)

| Passo | Estado |
|---|---|
| 1. Fleet aceita as duas audiências (`313940d`, `01b5455`, token pessoal com ambas) | feito, no ar |
| 2. Cliente `sufficit-fleet` criado (confidencial, mesmas permissões, `ept:introspection` por provisionamento administrativo no banco, como em 10/09) | feito; introspecção testada (`active=false` para token inválido, 401 com segredo errado) |
| 3. `fleet.api` emite as duas audiências (`sufficit_fleet`, `sufficit-fleet`) | feito 05/10 ~11:40 UTC |
| 4. ~~**A partir de 2026-10-12**~~ (ver 23/10) (tokens só com a audiência antiga vencidos; access token do Genius dura 7 dias): Fleet passa a usar `sufficit-fleet` — trocar `/etc/sufficit-fleet/identity.env` pelo conteúdo de `/etc/sufficit-fleet/identity-next.env` (já no node-a-ai, 600) e reiniciar o Fleet; conferir login e API | **agendado**: `fleet-rename-step4.timer` no node-a-ai, 2026-10-12 13:00 UTC (10:00 BRT), script `/usr/local/libexec/fleet-rename-step4.sh` — testa a credencial nova na introspecção antes, troca, reinicia e reverte sozinho se o Fleet não ficar pronto; resultado em `journalctl -t fleet-rename-step4` | **feito 23/10** com fallback legado (ver abaixo); timer desativado |
| 5. Tirar `sufficit_fleet` do recurso de `fleet.api`; no Identity, trocar `PersonalTokens__ScopeClientIds__1` (drop-in `45-fleet-api.conf`) para `sufficit-fleet`; Fleet com `Audiences=["sufficit-fleet"]` | pendente, depois do 4 |
| 6. Desativar/remover o cliente `sufficit_fleet` | pendente, depois de uma semana do 5 |

Trocar o passo 4 antes de 12/10 faria a introspecção responder `active=false`
para todo token emitido antes de 05/10 ~11:40 UTC.

Candidatos à mesma migração, um de cada vez: `sufficit_run_console`,
`sufficit_cloud_mobile(_api)`, `sufficit_ai_vault`, `sufficit_blazor_ai_bridge`,
`sufficit_background`, `sufficit_network_control`,
`sufficit_provisioning_credentials`, `sufficit_landing_pages`,
`sufficit_mobile_ai_models`, `sufficit_mobile_apps`,
`sufficit_endpoints_swagger_ui`, `sufficit_fleet_beta`. `dcr_*` e GUIDs são
gerados e ficam como estão.

## 12–13/10: passo 4 executado e revertido

O timer trocou o Fleet para `sufficit-fleet` em 12/10 13:00 UTC (Fleet pronto,
login redirecionando com `client_id=sufficit-fleet`). Em 13/10 a API recusou um
token pessoal do Fleet: tokens pessoais (`SufficitAPIUserAccess`) são duráveis e
os emitidos antes de 05/10 têm só `aud=sufficit_fleet`, então a introspecção
pelo cliente novo responde `active=false`. A janela de 7 dias só valia para os
access tokens comuns.

- 13/10: Fleet voltou ao cliente `sufficit_fleet` (API 200 de novo).
- Fleet `906bc46`: `Fleet:Identity:LegacyClientId/LegacyClientSecret` — se o
  cliente atual recebe `active=false`, a introspecção repete com o legado.
- Configuração final pronta em `/etc/sufficit-fleet/identity.env.target`
  (cliente novo + legado), a aplicar só com `906bc46` no ar.
- Remover o legado (passos 5 e 6) só depois que vencer o último token pessoal
  emitido antes de 05/10 ~11:40 UTC — conferir pela lista de tokens pessoais,
  não por prazo fixo.

## 23/10: passo 4 aplicado de novo, com fallback

Fleet no ar em `315927d` (contém `906bc46`). O `identity.env.target` de 13/10
estava desatualizado (ainda tinha `Fleet__Webhooks__github__ContextId`, que
saiu em 15/10), então o `identity.env` novo foi montado a partir do atual:
`ClientId=sufficit-fleet` + segredo de `identity-next.env`, mais
`LegacyClientId=sufficit_fleet` + segredo antigo. Backup:
`identity.env.bak-rename-20261023T134455Z`. `fleet-rename-step4.timer`
desativado.

Conferido 23/10 13:45 UTC: introspecção com o cliente novo 200
(`active=false` para token inválido); `readyz` 200; login redireciona com
`client_id=sufficit-fleet`; `/api/fleet/v1/contexts` 401 sem token e com token
inválido (passa pelos dois clientes); nenhum erro no journal.

Efeito colateral esperado: `SetApplicationName(ClientId)` troca o
Data Protection, então cada usuário entra de novo uma vez no navegador.

Passos 5 e 6 continuam pendentes até vencer o último token pessoal emitido
antes de 05/10 ~11:40 UTC.

### 23/10: o que ainda trava os passos 5 e 6

Tokens pessoais válidos emitidos antes de 05/10 ~11:40 UTC (tabela `tokens`,
`reference_id` preenchido, `application_id` nulo; payload é JWE, então a
audiência não aparece no banco — supor `sufficit_fleet` só):

| id (prefixo) | dono | descrição | vence (UTC) |
|---|---|---|---|
| `654cb44d` | uirison@aguasclarastelecom.com.br | Gestão sufficit | 2026-10-28 14:41 |
| `8b23df8d` | deborah@sufficit.com.br | Claude | 2026-11-30 03:00 |
| `83bf1230` | hugodeco@sufficit.com.br | code-server | 2026-12-31 03:00 |

Passo 5 só depois que esses três vencerem ou forem trocados por tokens novos
pelos donos (revogar sem combinar quebra a integração deles). Conferir de novo
com a mesma consulta antes de executar.
