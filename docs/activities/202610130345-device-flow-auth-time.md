# Device flow passa a carregar `auth_time` (credenciais delegadas)

Data: 2026-10-13 (UTC). Release `20261013T034401Z-a282b08` nos três nós
(app-node-1, app-node-2, app-node-3), uniforme pelo rolling deploy.

## Sintoma

Com a delegação ligada no cliente nativo, toda
autorização de executor caía no device flow com
`delegation_requires_recent_login`, mesmo logo após um login novo. Log do STS:
`Delegated credential refused for <sub> by client example-native-app:
missing_auth_time`.

## Causa

`DeviceController` montava o principal do device_code só com `sub`, id do
device code, escopos e recursos. O `DeviceCodeGrantHandler` projeta o contexto
de autenticação a partir desse principal (e do `HttpContext.User`, vazio no
polling), então tokens resgatados por device flow nunca tinham
`auth_time`/`amr`/`acr`. Os clientes desktop e móvel entram por device flow:
nenhum login deles podia delegar.

## Correção (`a282b08`)

Na aprovação, `IAuthenticationContextProjector.Project(result.Principal,
identity)`: a sessão do navegador que aprova é a autenticação do usuário para
essa concessão. `DeviceFlowTests` confere `auth_time` recente no `id_token`
resgatado (falha sem a correção). Suíte: 1676 aprovados, 1 ignorado.

## Validação

- Uniformidade do cluster (revisão, `/health`, `/health/ready`, certificado,
  JWKS) pelo `activate-cluster-release.sh`.
- `wwwroot` sem arquivo ilegível nos três nós; `/account/login` em Chrome real:
  22 recursos, nenhum ≥ 400.
- Tokens emitidos antes da correção continuam sem `auth_time`: delegação só
  depois de um login novo. Teste ponta a ponta da delegação pendente de um
  login do dono.

## Continuação 13/10: cliente do executor recebe `directives` (14:07 UTC)

Um resource server consumidor faz a introspecção com uma audiência que só o
escopo `directives` dá. O cliente do executor foi criado sem `directives`,
então toda introspecção de token de executor delegado era recusada ("issued to
a different client or for another resource server") e o executor ficava sem
acesso à API. `scp:directives` adicionado às permissões do cliente direto no banco
(com backup das permissões anteriores).
`identity.mcp` continua fora (decisão do dono 12/10).

Validação ponta a ponta: sessão de nuvem nova autorizada por delegação
(`method=delegated`, sem device flow), criada em ~25 s, e o executor chamou a
API usando a credencial delegada.
