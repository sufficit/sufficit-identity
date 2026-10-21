# Usuários de sistema

Um usuário de sistema é um usuário comum para todas as aplicações: tem `sub`,
claims, entitlements, papéis e responde no `/connect/userinfo`. A diferença é
que **ele nunca entra pela tela**. Senha, login externo, passkey, recuperação
e o grant `password` são recusados, com a mesma resposta de credencial
inválida.

Use para software que precisa agir como um usuário (agentes, executores,
integrações) sem uma pessoa por trás. Para software que não age como usuário,
continua existindo a conta de sistema de serviço (`/management/service-accounts`),
que é só um cliente OAuth.

Plano e decisões: [`docs/plans/PLAN-SYSTEM-USERS.md`](../plans/PLAN-SYSTEM-USERS.md).

## 1. Preparar o cliente (uma vez por software)

O software usa um cliente OAuth próprio do software (não um por usuário). Ele
precisa das permissões:

- `ept:token`
- `gt:refresh_token`
- `gt:urn:sufficit:params:oauth:grant-type:system-user-enrollment`
- `scp:<escopo>` para cada escopo que o software vai pedir

Pode ser público (recomendado com DPoP) ou confidencial.

## 2. Criar o usuário de sistema

Management → **Usuários de sistema** → *Novo usuário de sistema* (nome de
usuário e, opcionalmente, nome de exibição). Ou pela API:

```http
POST /api/system-users
{ "userName": "agent-github-engineer", "displayName": "GitHub engineer" }
```

`userId` (UUID) é opcional: permite reaproveitar um id que o chamador já usa
(por exemplo, o id do agente). Se já existir usuário com esse id, a resposta é
409; o identity nunca adota uma conta existente.

Entitlements, papéis e claims são dados como para qualquer usuário (página do
usuário). A criação fica auditada com o operador.

Capacidades: listar `identity.users.read`, criar `identity.users.create`,
desativar `identity.users.disable`, emitir e revogar credencial
`identity.users.reset`, entitlements `identity.claims.read`/`identity.claims.create`.

**Serviço de provisionamento.** `identity.system-users.manage` cobre todas essas
operações, **só** sobre usuários de sistema: criar, ativar/desativar, emitir e
revogar códigos e definir entitlements. Um usuário humano não é alcançado (404
nas rotas de usuário de sistema; as demais rotas exigem as capacidades gerais).
Dê a uma conta de serviço (`identity:client:roles`) um papel mapeado só para
ela em `RoleCapabilities`, por exemplo `"systemusers": ["identity.system-users.manage"]`.

**Entitlements:**

```http
PUT /api/system-users/entitlements?userId=<id>
{ "entitlements": ["aiuser:<contexto>"] }
```

Substitui o conjunto inteiro (o que não estiver na lista sai). Contexto em
qualquer grafia de UUID é gravado compacto (32 hex). `GET` na mesma rota lista.

## 3. Emitir o código de habilitação

Na página, *Credenciais* → cliente, rótulo (onde a credencial vai morar) e
validade do código (1 hora a 7 dias). O código aparece **uma única vez**. Ou:

```http
POST /api/system-users/enrollments?userId=<id>
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
  `DELETE /api/system-users/enrollments?userId=<id>&id=<enrollmentId>`.
- **Desativar** o usuário: *Desativar*, ou
  `PATCH /api/system-users/toggle?userId=<id>&enabled=false` (`enabled` vazio
  inverte o estado). Desativar revoga todas as credenciais e impede novas. Ao
  reativar, emita um novo código.

Tudo é auditado com o operador e a correlação.

## Implantação

Aplicar `docs/migration/sql/100-add-system-users.sql` antes dos binários que
contêm esta funcionalidade. Todo login consulta a marcação de usuário de
sistema, então a tabela precisa existir.
