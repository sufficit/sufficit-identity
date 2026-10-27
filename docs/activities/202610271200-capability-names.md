# Nomes de capabilities

**27/10/2026.** Implementado no branch `work/capability-names`; não publicado.
Decidido com o dono do produto: limpar os nomes do catálogo e criar duas
capabilities restritas a usuários de sistema.

## Regra

Toda capability é `identity.<recurso>.<ação>` ou `identity.<recurso>.<qualificador>`,
com no máximo mais um nível (`identity.users.mfa.reset`). Cada segmento é **uma
palavra minúscula**: sem hífen e sem palavra composta. Todo valor de
`ManagementCapabilities.All` casa com `^identity(\.[a-z]+){2,3}$`
(`ManagementCapabilityNamingTests`).

## Renomeações

| Antigo | Novo |
| --- | --- |
| `identity.users.reset-mfa` | `identity.users.mfa.reset` |
| `identity.system-users.manage` | `identity.users.system` |
| `identity.trusted-proxies.read` / `.manage` | `identity.proxies.read` / `.manage` |
| `identity.vault.secrets.read` / `.manage` / `.resolve` | `identity.secrets.read` / `.manage` / `.resolve` |
| `identity.management.tokens.read` / `.issue` / `.revoke` | `identity.tokens.read` / `.issue` / `.revoke` |
| `token_exchange.delegated_credential` (só rótulo de auditoria) | `identity.credentials.delegate` |

As constantes antigas (`UsersResetMfa`, `SystemUsersManage`, `TrustedProxies*`,
`VaultSecrets*`, `ManagementTokens*`, `OperatorTokens*`, `UsersResetPassword`)
ficam como aliases `[Obsolete]`. O rótulo de credencial delegada não é
capability concedível e não entra em `All`; linhas de auditoria antigas mantêm
o valor antigo e a tela de auditoria mostra o novo.

Nada mais no catálogo tinha hífen ou palavra composta (`maintenance`,
`provisioning`, `confirmation`, `authorizations` são uma palavra cada).

## Qualificador `.system`

Quer dizer "toda ação do recurso, mas só em usuários de sistema" — usuários
reconhecidos por `SystemUserStore.WhereSystemUser` (sem e-mail, senha, login
externo nem passkey), a mesma regra do login e da API de usuários de sistema.

- `identity.users.system`: o que `identity.system-users.manage` fazia. Satisfaz
  users read/create/disable/reset só em `SystemUserManagementService`, porque
  toda operação cria um usuário de sistema ou procura o alvo entre eles.
- `identity.claims.system` (nova): em `/api/claims`, satisfaz claims
  read/create/update/delete só quando o dono da claim é usuário de sistema. A
  capability geral é tentada primeiro; sem ela, o qualificador exige que o dono
  seja usuário de sistema, e para qualquer outro é recusado
  (`claim_owner_not_system_user`, 403, auditado nas alterações como as demais
  recusas). A listagem sem `userId` só mostra claims de usuários de sistema.
  Tipos de claim reservados e a política de principal protegido continuam
  valendo (`ClaimsSystem` entrou em `ProtectedPrincipalCapabilities`).
  Código: `ClaimManagementService.SystemUsers.cs`.

## Rotas

`SystemUsersController` responde em `api/users/system` (canônica) e
`api/system-users` (alias): listar, criar, `toggle`, `enrollments`, com os mesmos
parâmetros de query string. O segmento literal tem precedência sobre
`api/users/{id}`, então `GET api/users/system` é a lista de usuários de sistema.

## Janela de legado

- `ManagementCapabilities.Normalize` (dados em `LegacyNames`) converte os nomes
  antigos em todas as entradas: claims `permission` (inclusive tokens
  temporários já emitidos), `RoleCapabilities`, papéis de `ServicePrincipals`,
  emissão e listagem de tokens temporários, tela de contas de serviço,
  preenchimento por query string, o próprio avaliador e a apresentação na
  console. Nenhuma saída nova usa nome antigo.
- `GET/PUT /api/system-users/entitlements` continuam funcionando, só na rota
  legada, marcados como obsoletos (`SystemUserEntitlementsController`), e ainda
  aceitam `identity.users.system`. O caminho novo é `/api/claims` com
  `identity.claims.system`. Remover quando nenhum provisionador usar mais.
- A configuração de produção (`deploy/local/appsettings.json`) continua
  funcionando com os nomes antigos, mas deve ser atualizada para os novos.

## Validação

Suíte completa verde (`dotnet test src/tests/Sufficit.Identity.Tests.csproj`).
Testes novos: todo nome antigo normaliza para o novo (em claim e em
`RoleCapabilities`), todo valor de `All` segue a regra, `identity.claims.system`
cria, lê e remove claim de usuário de sistema e é recusado em pessoa (com
auditoria), `identity.users.system` funciona na rota nova, `api/users/system` e
`api/system-users` respondem, e um token temporário emitido com nome antigo é
listado com o nome novo.
