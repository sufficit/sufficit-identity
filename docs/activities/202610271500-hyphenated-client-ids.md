# Client ids com hífen (27/10/2026)

Decisão do titular: todo `client_id` usa hífen, como `sufficit-fleet` (migrado
em 23/10). Escopos e audiências ficam como estão; só o id do cliente muda.

## Como

Mesmo caminho do `sufficit-fleet`, sem tocar no cliente antigo:

1. Cópia de cada aplicação com o id novo (mesmas permissões, URIs,
   propriedades — inclusive `identity:client:roles`), e cópia da credencial
   ativa em `oauthclientcredentials` para os confidenciais. O segredo é o
   mesmo, então o consumidor só troca o id.
2. Consumidor passa a usar o id novo.
3. Cliente antigo fica ativo até não emitir mais token; depois é desativado
   (`sufficit:disabled`) e, mais tarde, apagado.

O registro dinâmico passou a gerar `dcr-<48 hex>` em vez de
`dcr_<base64url>` (que também podia conter `_`). Registros existentes mantêm o
id: pertencem a quem registrou.

## Clientes

| Antigo | Novo | Consumidor |
|---|---|---|
| `sufficit_ai_vault` | `sufficit-ai-vault` | `/etc/sufficit/ai/vault-client.env` nos 3 nós AI |
| `sufficit_provisioning_credentials` | `sufficit-provisioning-credentials` | Provisioning nos 3 `*-apps`; endpoints aceita os dois |
| `sufficit_background` | `sufficit-background` | background (eveo) |
| `sufficit_run_console` | `sufficit-run-console` | run console (eveo) |
| `sufficit_landing_pages` | `sufficit-landing-pages` | `landing-pages.env` (eveo) |
| `sufficit_network_control` | `sufficit-network-control` | `network-control.env` (castrum) |
| `sufficit_endpoints_swagger_ui` | `sufficit-endpoints-swagger-ui` | endpoints |
| `mcp_vscode_proxy` | `mcp-vscode-proxy` | endpoints; sufficit-ai (proxy desligado) |
| `sufficit_mobile_ai_models` | `sufficit-mobile-ai-models` | sem consumidor no código |
| `sufficit_mobile_apps` | `sufficit-mobile-apps` | sem consumidor no código |

Sem cópia, a desativar: `sufficit_fleet_beta` (nenhum token emitido).

`skoruba_identity_admin` e `skoruba_identity_admin_api_swaggerui` (o admin
antigo, que não existe mais) foram **apagados** em 27/10 com o aval do
titular: nenhum token, autorização, uso diário nem linha de log em 30 dias
nos três nós. Cópia das linhas em
`/root/applications-skoruba-20261027.tsv` no `eveo-apps` (0600).

## Execução (27/10)

- Cópias criadas no banco; `sufficit-ai-vault` testado com `client_credentials`
  e vault (200) antes da troca.
- Nós AI trocados e reiniciados um a um; depois disso só o id novo emite token.
- Landing pages, network control, run console e background reiniciados com o
  id novo; os quatro redirecionam ao `/connect/authorize` com ele.
- Endpoints `ed575ef` nos 3 `*-apps` (aceita os dois ids do provisioning);
  depois o Provisioning nos 3 nós. Token do id novo autorizado no
  `/telephony/endpoint/provisioning/byid` em 9 chamadas seguidas (204, nenhum
  403).
- Backups das configs: `*.bak-20261027-underscore` ao lado de cada arquivo
  (background: `/opt/appsettings.background.bak-20261027-underscore`).

Pendente: desativar os ids antigos depois que pararem de emitir token, com o
aval do titular.

## Escopos com ponto (27/10)

Escopos usam ponto como separador. Os sucessores já existiam no banco desde
02/09 (`network.control`, `background.jobs`, `ai.bridge`,
`personal.tokens.manage`); faltava mover os consumidores.

- `sufficit_fleet_beta` apagado (último uso 10/09, 1 autorização antiga;
  cópia em `/root/applications-fleet-beta-20261027.tsv`).
- **background:** API aceita `background.jobs` e `sufficit_background`, e as
  audiências `sufficit-background` e `sufficit_background_api` (background
  `eaf0f7a`, no ar no eveo). `background.jobs` passou a declarar as duas
  audiências; o cliente `sufficit-background` ganhou o escopo e o login já o
  pede.
- **network-control:** cliente ganhou `network.control`; código pede só ele
  (`8ec2bc4`), mas a Web em produção pede os dois até o próximo deploy dela:
  o binder anexa o config ao array default do `WebOptions`. O deploy traria
  também a SUI 2.* de setembro, por isso ficou para depois.
- **landing pages:** `personal_tokens.manage` é morto (o Identity só conhece
  `personal.tokens.manage`). Código parou de pedir (`ff13836`). Apagar o
  escopo derrubou o login do landing por ~5 min (`invalid_scope`): o binário
  em produção ainda pede pelo default do código. Escopo e permissão
  restaurados; removem-se depois do deploy do landing.
- **`sufficit_ai_openai_bridge`:** fica. Cinco autorizações do Genius de
  agosto ainda renovam token (uma hoje) e o executor herda o escopo por
  delegação; tirar a permissão derrubaria esses dispositivos.

Pendentes: deploy do landing e da Web do network-control; depois remover
`personal_tokens.manage`, `sufficit_network_control` e `sufficit_background`
(escopo, permissões e audiência `sufficit_background_api`), e desativar os
client ids antigos.
