# Device flow passa a carregar `auth_time` (delegação do Genius)

Data: 2026-10-13 (UTC). Release `20261013T034401Z-a282b08` nos três nós
(eveo-apps, apoint-apps, castrum-apps), uniforme pelo rolling deploy.

## Sintoma

Com `WorkspaceExecution:DelegatedCredential:Enabled=true` no Genius, toda
autorização de executor caía no device flow com
`delegation_requires_recent_login`, mesmo logo após um login novo. Log do STS:
`Delegated credential refused for <sub> by client sufficit-ai-genius:
missing_auth_time`.

## Causa

`DeviceController` montava o principal do device_code só com `sub`, id do
device code, escopos e recursos. O `DeviceCodeGrantHandler` projeta o contexto
de autenticação a partir desse principal (e do `HttpContext.User`, vazio no
polling), então tokens resgatados por device flow nunca tinham
`auth_time`/`amr`/`acr`. Desktop e celular do Genius entram por device flow:
nenhum login do Genius podia delegar.

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
