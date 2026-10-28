# Operador só concede o escopo que tem; segredo por referência ao Vault (28/10/2026)

Plano A2 ("Operator-aware client scope and secret authorization"), parte de
código. O que falta é operacional e continua no plano.

## Por quê

O piso de escopos reservados (`ReservedApiScopes`) impedia qualquer cadastro
de cliente com `identity.management`/`scim`, mas fora dele qualquer operador
com `identity.clients.create` colocava qualquer escopo em qualquer cliente —
inclusive escopos de API que davam a esse cliente mais autoridade do que o
operador tinha. E o contrato HTTP de criação só aceitava o segredo em texto
claro no corpo da requisição.

## Decisão única de concessão de escopo

- `IClientScopeGrantAuthorization` / `ClientScopeGrantAuthorization`
  (`Application.Abstractions/Security/ClientScopeGrantAuthorization.cs`).
  Entrada: operador (sujeito + capacidades **resolvidas** pelo
  `IManagementEntitlementResolver` — papéis, claims `permission`, subconjunto
  de token de operador, papéis de usuário de sistema), cliente alvo, grants,
  escopos pedidos e escopos atuais.
- Ordem por escopo: piso reservado → `scope_reserved` (sempre recusado, também
  em `Observe`); não privilegiado ou já presente no cliente → permitido; sem
  operador → `scope_grant_operator_required`; sem a capacidade →
  `scope_grant_capability_missing`. Só o que entra de novo é expansão.
- Escopos privilegiados por implantação:
  `Sufficit:Identity:Management:ClientScopeGrants:PrivilegedScopes`
  (`Scope` + `Capability` opcional). Capacidade nova `identity.scopes.grant`
  é o padrão; capacidade fora do catálogo ou escopo repetido derruba a
  composição. Lista vazia por padrão.
- `ClientScopeGrants:Mode`: `Observe` (padrão) ou `Enforce`.

### Entradas cobertas

| Entrada | Operador | Recusa em `Enforce` | Registro |
| --- | --- | --- | --- |
| Management criar/editar (API e tela) | sessão | `403`, `reasonCode`, `requiredPermission` | auditoria + log |
| Provisionamento (preview/apply) | sessão ou token de provisionamento | `403`; todos os clientes do manifesto auditados antes | auditoria + log |
| Registro dinâmico | nenhum (mais restrito) | `400 invalid_client_metadata` + `reason_code` | auditoria (`source:dynamicregistration`) + métrica + log |
| CIMD | nenhum | escopo descartado do cliente | log |

Linha de auditoria (`ClientScopeGrantAudit`, em `core`): `Capability` = a que
faltou, `OperationOutcome` `denied`/`observed`, `AuthorizationOutcome`
`denied`/`allowed:scope_grant_observe`, sem nome/e-mail do operador,
`AfterJson` com origem, modo, grants e escopos recusados.

Postura (D4): com escopos privilegiados e `Observe`, aviso
`management-client-scope-grants-observe` (advisory — não bloqueia o
arranque). Sem escopos privilegiados o modo não decide nada e nada é
reportado, então a produção atual continua sem achado.

## `secretReference` e o adaptador de texto claro

- `POST /api/clients` e `PUT /api/clients/{clientId}` aceitam
  `secretReference: { name, contextId }` (`ManagementClientSecretReference`
  no comando). Resolução por `IManagementClientSecretReferenceResolver` →
  `VaultClientSecretReferenceResolver`, que usa o
  `IVaultSecretsManagementService` existente: o operador precisa de
  `identity.secrets.resolve` e do namespace, e a resolução fica no diário do
  Vault. Nada novo no Vault foi necessário.
- O segredo vira hash na aplicação; a origem fica na propriedade
  `identity:management:secret-reference`. Na edição só troca segredo de
  aplicação confidencial.
- `clientSecret` em texto claro no `POST`: `PlaintextClientSecretAdapter` no
  controller HTTP. Antes de
  `Sufficit:Identity:Management:ClientSecrets:PlaintextExpiresAtUtc`
  (padrão `2027-04-30T00:00:00Z`) aceita com aviso
  `client_secret_plaintext_deprecated`; depois recusa
  `client_secret_plaintext_expired`. Os dois juntos:
  `client_secret_source_ambiguous`. O assistente de criação (segredo gerado
  no servidor) e a rotação não passam pelo adaptador.

## Testes

`ClientScopeGrantAuthorizationTests` (decisão, opções, postura, Management
criar/editar/HTTP, provisionamento, registro dinâmico) e
`ClientSecretReferenceTests` (adaptador antes/depois da validade, ambiguidade,
referência criando e trocando o segredo, segredo real do Vault).
`ClientsControllerTests.Create_and_delete_append_redacted_audit_events` passa
a esperar a linha de aviso do adaptador.

## Produção (28/10)

Publicado nos três nós em `6beda5b`. A lista de escopos privilegiados foi
configurada em `Observe` no `appsettings.Production.json` de cada nó (o deploy
preserva o arquivo; cópia `*.bak-20261028-scopegrants`). Os três reiniciaram um
por vez e registraram o aviso esperado `management-client-scope-grants-observe`.

Regra usada: é privilegiado o escopo cujo portador age além dos dados do
próprio usuário logado — dados de outros usuários ou do cliente inteiro,
dinheiro, infraestrutura, delegação ou publicação. Escopo que só libera claims
ou age pelo usuário logado fica livre. Quem já tem o escopo o mantém, então a
lista só controla concessões novas.

| Privilegiado | Motivo |
|---|---|
| `identity.scim`, `identity.tokens`, `identity.vault`, `identity.mcp` | administração do identity, emissão de token, segredos |
| `personal.tokens.manage`, `genius.executor.delegate` | cria credencial ou delega a autoridade do usuário |
| `provisioning.manage`, `provisioning.installation` | provisionamento de dispositivos e contas |
| `network.control`, `background.jobs` | infraestrutura e jobs |
| `telephony.billing`, `endpoints.invoices`, `sufficit.endpoints.n8n.asaas-invoices`, `policies` | dinheiro e política do cliente inteiro |
| `sufficit.landing.publish` | publicação pública |
| `fleet.api`, `ai.bridge`, `sufficit_ai_openai_bridge` | orquestração de agentes e modelos pagos pelo cliente |

Livres: `openid`, `profile`, `email`, `address`, `roles`, `offline_access`,
`directives`, `entitlements`, `ai.user`, `chrome.phone`, `endpoints.phone`,
`endpoints.webcallback`. `identity.management` e `scim` já são o piso
reservado. Todos usam a capacidade padrão `identity.scopes.grant`; separar uma
capacidade só quando alguém que não é administrador pleno precisar conceder um
escopo.

## Pendências (operacionais, no plano)

- Conciliar as recusas observadas (~04/11) e passar a `Enforce`.
- Migrar quem ainda manda `clientSecret` (linhas
  `client_secret_plaintext_deprecated`) e remover o adaptador depois da data.
- Inventário dos manifestos reais e adoção explícita dos clientes
  gerenciados.
- A rotação (`/secret/rotate`) e credenciais adicionais
  (`/credentials`) ainda aceitam segredo informado pelo operador; não fazem
  parte do contrato de criação/edição deste item.
