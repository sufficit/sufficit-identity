# Contas de serviço viram usuários de sistema (28/10/2026)

## Por quê

Havia dois modelos de autoridade para software: o **usuário de sistema**
(usuário sem e-mail, senha nem login, com `sub`, papéis e claims) e a **conta
de serviço** (cliente OAuth com `client_credentials` e papéis gravados no
próprio cliente, `identity:client:roles`, tela `/management/service-accounts`).
O segundo emitia token sem `sub`, que quebrava userinfo e auditoria por usuário,
e dava dois lugares onde conceder gestão. Decisão do titular: um modelo só.

O cliente OAuth passa a só **autenticar**. Software de servidor continua com
`client_credentials` e o mesmo segredo, mas o cliente fica **vinculado a um
usuário de sistema** (`identity:client:system-user`); o token traz o `sub`
desse usuário e a autoridade vem dos papéis dele.

## Fase 1 (`9e82828`, no ar em 28/10 nos três nós)

- `client_credentials` de cliente vinculado emite token do usuário de sistema;
  vínculo a quem pode entrar pela tela, ou a usuário desativado, recusa o
  cliente (`unauthorized_client`).
- `SystemUserEntitlementResolver`: capacidades do usuário de sistema vêm dos
  papéis lidos **na hora** (tirar papel ou desativar vale na próxima chamada) e
  são isentas de MFA. O portão de MFA da política passou a aceitar quem tem
  concessão isenta, sem caso especial para papéis de cliente.
- Papéis do cliente ainda contavam, para a transição sem queda.

## Migração em produção (28/10)

- Usuários de sistema criados pela API (autenticado como o cliente de
  provisionamento do Fleet): `sufficit-ai-vault`, `sufficit-endpoints-vault`,
  `fleet-credentials`, `voice-claims-reader`.
- Papéis em `userroles`, os mesmos que os clientes tinham:
  `mobilecloudadministrator` (os três primeiros), `systemusers` e
  `oauthreader` (`fleet-credentials`), `claimsreader`
  (`voice-claims-reader`). `systemusers`, `oauthreader` e `claimsreader` não
  existiam na tabela `roles` e foram criados.
- Os 4 clientes vinculados (`sufficit-ai-vault`, `sufficit-endpoints-vault-v3`,
  o cliente de credenciais do Fleet e o leitor de claims da voz); identity
  reiniciado nos três nós para o cache. Backup das propriedades:
  `/root/applications-before-system-user-binding-20261028.tsv` no
  `eveo-apps` (0600).
- Conferido com os segredos de produção, sem trocar nada nos consumidores:
  vault da AI `list`/`resolve` 200 e userinfo com o `sub` do usuário; Fleet
  `/api/users/system` e `/api/clients` 200; vault do endpoints userinfo 200;
  leitor de voz `/api/claims` 200.

## Fase 2 (esta mudança)

- Vínculo pela tela e pela API, sem SQL: `GET/PUT/DELETE
  /api/users/system/clients?userId=&clientId=` (também em
  `/api/system-users/clients`), e a seção *Clientes que agem como este usuário*
  na página do usuário de sistema. Exige a capacidade de credencial do usuário
  e `identity.clients.update`; cliente precisa ser confidencial com
  `client_credentials`; vinculado a outro usuário = 409.
- Removidos: tela, serviço, controller e contratos de contas de serviço;
  `ServicePrincipalEntitlementResolver`, a leitura de papéis do cliente e a
  opção `ClientRolesPropertyName`. `/management/service-accounts` redireciona
  para usuários de sistema.
- Trava: `ClientAuthorityContractTests` falha se código de produção voltar a
  ler `identity:client:roles`. Testes ponta a ponta em
  `SystemUserClientTests`: token com o usuário, papel sem MFA e revogado na
  hora, recusa de pessoa/desativado, cliente sem vínculo sem acesso, e a API de
  vínculo.

Depois do deploy da fase 2: apagar a propriedade `identity:client:roles` dos
clientes em produção (já sem efeito).
