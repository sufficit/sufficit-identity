# Usuários de sistema

Um usuário de sistema é um **usuário comum sem e-mail, sem senha, sem login
externo e sem passkey**. Para todas as aplicações é um usuário como outro
qualquer: tem `sub`, claims, entitlements, papéis e responde no
`/connect/userinfo`. Como não tem com o que entrar, **nunca entra pela tela**;
as rotas de login ainda o recusam como defesa extra. Não há marcação separada:
dar e-mail, senha, login externo ou passkey a ele o torna um usuário comum.

Use para todo software sem uma pessoa por trás (agentes, executores,
integrações, serviços de servidor). O cliente OAuth do software só o
autentica; o que ele pode fazer vem do usuário de sistema, como para qualquer
pessoa. Não existe autoridade dada a um cliente: a antiga tela de contas de
serviço (`/management/service-accounts`, que redireciona para cá) e os papéis
gravados no cliente foram aposentados.

Há duas formas de o software obter o token do usuário de sistema:

- **Serviço de servidor com segredo** (`client_credentials`): vincule o
  cliente confidencial ao usuário de sistema (seção 6). O software continua
  usando o mesmo `client_id` e segredo; o token passa a trazer o usuário.
- **Agente ou dispositivo** sem segredo fixo: código de habilitação trocado por
  refresh token (seções 3 e 4).

Decisões e registro: [`docs/activities/202610211700-system-users.md`](../activities/202610211700-system-users.md).

## 1. Preparar o cliente (uma vez por software)

O software usa um cliente OAuth próprio do software (não um por usuário). Ele
precisa das permissões:

- `ept:token`
- `gt:refresh_token`
- `gt:urn:sufficit:params:oauth:grant-type:system-user-enrollment`
- `scp:<escopo>` para cada escopo que o software vai pedir

Pode ser público (recomendado com DPoP) ou confidencial.

A API de clientes aceita o grant nativo em `grantTypes`, tanto como
`urn:sufficit:params:oauth:grant-type:system-user-enrollment` quanto com
prefixo `gt:`. Ao editar scopes com `PUT /api/clients/{clientId}`, preserve
os grants existentes e envie `expectedVersion`. Esse grant deriva a permissão
`ept:token`; grants desconhecidos continuam recusados, assim como grants
fora da lista permitida pela origem do cadastro.

## 2. Criar o usuário de sistema

Management → **Usuários de sistema** → *Novo usuário de sistema* (nome de
usuário e, opcionalmente, nome de exibição). Ou pela API:

```http
POST /api/users/system
{ "userName": "agent-github-engineer", "displayName": "GitHub engineer" }
```

Rota canônica: `/api/users/system` (listar `GET`, criar `POST`,
`PATCH …/toggle`, `…/enrollments`). `/api/system-users` continua respondendo
como alias, com os mesmos parâmetros de query string (`userId=…`).

`userId` (UUID) é opcional: permite reaproveitar um id que o chamador já usa
(por exemplo, o id do agente). Se já existir usuário com esse id, a resposta é
409; o identity nunca adota uma conta existente.

Quem criou fica no evento de auditoria `system_user_created`, que **não
expira** (os demais eventos seguem a retenção padrão de 15 dias).

Entitlements, papéis e claims são dados como para qualquer usuário (página do
usuário). A criação fica auditada com o operador.

Capacidades: listar `identity.users.read`, criar `identity.users.create`,
desativar `identity.users.disable`, emitir e revogar credencial
`identity.users.reset`; entitlements (claims) `identity.claims.*`.

**Serviço de provisionamento.** O qualificador `.system` quer dizer "toda ação
do recurso, mas só em usuários de sistema":

- `identity.users.system` cobre criar, ativar/desativar, listar e emitir e
  revogar códigos, **só** sobre usuários de sistema. Um usuário humano não é
  alcançado (404 nas rotas de usuário de sistema; as demais rotas exigem as
  capacidades gerais).
- `identity.claims.system` cobre consultar, atribuir, editar e remover claims
  em `/api/claims`, **só** quando o dono da claim é usuário de sistema. Em
  qualquer outra conta é recusado (403, auditado nas alterações). Tipos de
  claim reservados (`permission`, `scope`, …) continuam proibidos.

Dê ao usuário de sistema do serviço de provisionamento um papel mapeado só
para isso em `RoleCapabilities`, por exemplo
`"systemusers": ["identity.users.system", "identity.claims.system"]`. Papéis
são dados no banco (`userroles`), como para pessoas; o Identity não atribui
papéis por nenhuma API. Para software, os papéis são lidos a cada chamada (tirar
o papel ou desativar o usuário vale na próxima) e o que eles concedem não exige
MFA.
O nome antigo `identity.system-users.manage` ainda é aceito e normalizado para
`identity.users.system`.

**Entitlements** são claims `entitlements` comuns, uma por valor:

```http
POST /api/claims
{ "userId": "<id>", "type": "entitlements", "value": "aiuser:<contexto compacto>" }

GET    /api/claims?userId=<id>
DELETE /api/claims?id=<claimId>      (ou /api/claims/<claimId>)
PUT    /api/claims?id=<claimId>      (ou /api/claims/<claimId>)
```

**Rota legada (obsoleta, só durante a transição):**

```http
PUT /api/system-users/entitlements?userId=<id>
{ "entitlements": ["aiuser:<contexto>"] }
```

Substitui o conjunto inteiro (o que não estiver na lista sai). Contexto em
qualquer grafia de UUID é gravado compacto (32 hex). `GET` na mesma rota lista.
Existe só em `/api/system-users` (não em `/api/users/system`) e ainda aceita
`identity.users.system`; migre para `/api/claims` com `identity.claims.system`.

## 3. Emitir o código de habilitação

Na página, *Credenciais* → cliente, rótulo (onde a credencial vai morar) e
validade do código (1 hora a 7 dias). O código aparece **uma única vez**. Ou:

```http
POST /api/users/system/enrollments?userId=<id>
{ "clientId": "<client_id do software>", "label": "pod github-engineer", "lifetimeHours": 24 }
```

O código (`sys_enroll_…`) serve uma vez e só para aquele cliente. No banco fica
só o hash.

## 4. O software troca o código pela credencial

```http
POST /connect/token
Content-Type: application/x-www-form-urlencoded
DPoP: <prova DPoP com a chave do software>     (recomendado)

grant_type=urn:sufficit:params:oauth:grant-type:system-user-enrollment
&enrollment_code=sys_enroll_...
&client_id=<client_id>
&scope=<escopos>                                  (opcional; padrão: os do cliente)
```

Resposta: `access_token` e `refresh_token` em nome do usuário de sistema. Com
prova DPoP, a credencial fica presa a essa chave: todo refresh precisa de prova
com a mesma chave. O operador nunca vê a credencial de longa duração.

**Habilitar em nome de um dispositivo.** Quando quem troca o código não é quem
vai usar a credencial (um provisionador que entrega o refresh token a um
executor cuja chave nunca sai dele), envie `dpop_jkt=<thumbprint RFC 7638 da
chave do dispositivo>` no lugar da prova. A credencial fica presa a essa chave;
o provisionador não consegue usá-la. `dpop_jkt` inválido, ou diferente da chave
de uma prova enviada junto, é recusado sem gastar o código.

Depois disso, o software usa o grant `refresh_token` normalmente. A credencial
tem prazo absoluto (`Sufficit:Identity:SystemUsers:CredentialLifetimeDays`,
padrão 365) que o refresh não estende; perto do fim, emita um novo código.

## 5. Revogar e desativar

- **Revogar** um código ou credencial: *Credenciais* → *Revogar*, ou
  `DELETE /api/users/system/enrollments?userId=<id>&id=<enrollmentId>`.
- **Desativar** o usuário: *Desativar*, ou
  `PATCH /api/users/system/toggle?userId=<id>&enabled=false` (`enabled` vazio
  inverte o estado). Desativar é o **lockout comum** de qualquer usuário;
  revoga todas as credenciais e impede novas. Ao reativar, emita um novo código.

Tudo é auditado com o operador e a correlação.

## 6. Cliente de servidor agindo como o usuário (client_credentials)

O cliente precisa ser **confidencial** e ter `gt:client_credentials`. Na
página do usuário de sistema, *Credenciais* → *Clientes que agem como este
usuário* → informe o `client_id` e vincule. Ou pela API (identificadores na
query string):

```http
GET    /api/users/system/clients?userId=<id>
PUT    /api/users/system/clients?userId=<id>&clientId=<client_id>
DELETE /api/users/system/clients?userId=<id>&clientId=<client_id>
```

(também em `/api/system-users/clients`). Vincular e desvincular exigem as duas
capacidades: a de credencial do usuário (`identity.users.reset`, ou
`identity.users.system`) e `identity.clients.update`, porque mudam o cadastro
do cliente. Um cliente vinculado a outro usuário responde 409: desvincule lá
antes. O vínculo fica na propriedade `identity:client:system-user` do cliente.

Na emissão, se o usuário vinculado não existir, estiver desativado ou tiver
ganhado como entrar (e-mail, senha, login externo, passkey), o cliente é
recusado (`unauthorized_client`) em vez de receber um token sem usuário.

## 7. Serviço que lê o Vault compartilhado

O Vault compartilhado (`/api/vault/secrets`, contextos como `global`) aceita o
escopo de gestão **ou** o escopo estreito `identity.vault`, este **só quando o
token é de um cliente vinculado a um usuário de sistema**. O serviço não precisa
de `identity.management` (reservado, que nenhum cadastro novo recebe) nem de
toda a superfície administrativa (menor privilégio, RFC 9700 §2.3).

1. Cliente confidencial com `gt:client_credentials` e `scp:identity.vault`.
2. Usuário de sistema com um papel cujas capacidades bastem. Papéis em uso:
   `vault.secrets.reader` (`identity.secrets.read` e `identity.secrets.resolve`,
   só lê) e `vault.secrets.manager` (os mesmos mais `identity.secrets.manage`,
   lê e grava). Atribua no banco (`userroles`); as capacidades vêm de
   `RoleCapabilities` na configuração dos nós.
3. Vínculo do cliente ao usuário (seção 6).

Nomes de segredo exigem ao menos uma `/` literal na rota
(`PUT /api/vault/secrets/apps/meu-servico/token`); `%2F` não é aceito.

O escopo estreito na credencial delegada de uma pessoa (agente pessoal) continua
limitado ao Vault pessoal: aqui ele é recusado. O que o serviço lê ou altera
segue as capacidades dos papéis do usuário de sistema, avaliadas a cada chamada.

## Implantação

Base nova: `001`. Base que tem `100-add-system-users.sql`: aplicar
`101-add-audit-event-expiry.sql`, publicar os binários em todos os nós e só
então aplicar `102-system-users-as-ordinary-users.sql` (os binários anteriores
leem `systemusers` em todo login).
