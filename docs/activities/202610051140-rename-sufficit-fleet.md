# Renomear `sufficit_fleet` para `sufficit-fleet` (em andamento)

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
| 4. **A partir de 2026-10-12** (tokens só com a audiência antiga vencidos; access token do Genius dura 7 dias): Fleet passa a usar `sufficit-fleet` — trocar `/etc/sufficit-fleet/identity.env` pelo conteúdo de `/etc/sufficit-fleet/identity-next.env` (já no node-a-ai, 600) e reiniciar o Fleet; conferir login e API | pendente |
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
