# Escopos privilegiados e segredo por referência ao Vault

Duas regras do cadastro de aplicações OAuth (plano A2):

- um operador só coloca numa aplicação o escopo privilegiado que ele próprio
  pode conceder;
- o segredo de uma aplicação nova chega por **referência a um segredo do
  Vault**, não em texto claro.

## Escopos privilegiados

A mesma decisão vale para as quatro entradas que gravam escopos num cliente:
criação/edição pelo Management (API e tela), aplicação/pré-visualização de
manifesto de provisionamento, registro dinâmico (`/connect/register`) e
cliente por documento de metadados (CIMD).

Ordem da decisão, por escopo pedido:

1. **Piso reservado** — `Management:ReservedApiScopes` (por padrão
   `identity.management` e `scim`). Recusado sempre, em qualquer modo e para
   qualquer operador: `scope_reserved`.
2. Escopo que não é privilegiado, ou que o cliente **já tem** — permitido.
   Manter um escopo não é expansão; só o que entra de novo precisa de
   autoridade.
3. Sem operador (registro dinâmico, CIMD, chamada sem sessão) —
   `scope_grant_operator_required`.
4. Operador sem a capacidade exigida — `scope_grant_capability_missing`.

As capacidades do operador são as **resolvidas** pelo Management: papéis
mapeados, claims `permission`, o subconjunto delegado num token de operador e
os papéis de um usuário de sistema. Um token de provisionamento só carrega as
duas capacidades de provisionamento e, por isso, não concede escopo
privilegiado novo.

### Configuração

```json
{
  "Sufficit": {
    "Identity": {
      "Management": {
        "ClientScopeGrants": {
          "Mode": "Observe",
          "PrivilegedScopes": [
            { "Scope": "reports.admin" },
            { "Scope": "ledger.write", "Capability": "identity.secrets.manage" }
          ]
        }
      }
    }
  }
}
```

- Sem `Capability`, o escopo exige `identity.scopes.grant` (capacidade nova do
  catálogo; administrador pleno já a tem).
- Capacidade fora do catálogo ou escopo repetido impede a inicialização.
- A lista começa vazia: sem configuração, nada além do piso é privilegiado.

### Rollout

- `Observe` (padrão): a recusa é registrada e a operação segue. Linha de
  auditoria com `operationOutcome=observed`,
  `authorizationOutcome=allowed:scope_grant_observe`.
- `Enforce`: a operação é recusada. Management e provisionamento respondem
  `403` com `reasonCode` e `requiredPermission`; o registro dinâmico responde
  `400 invalid_client_metadata` com `reason_code`; o CIMD cria o cliente sem
  o escopo recusado.

Cada recusa (observada ou aplicada) grava uma linha em
`managementauditevents`: `capability` = capacidade que faltou, `resourceId` =
client id, `reasonCode` estável e, em `afterJson`, origem, modo, grants e os
escopos recusados. O registro dinâmico usa `operatorSubject =
source:dynamicregistration` e soma no contador
`identity.security.policy.decisions` (`policy=client_scope_grant`). O CIMD só
registra em log.

Com escopos privilegiados configurados e modo `Observe`, a checagem de postura
aponta `management-client-scope-grants-observe` (aviso, não bloqueia).

Para passar a `Enforce`: consultar as linhas observadas
(`reasonCode like 'scope_grant_%' and operationOutcome = 'observed'`), conceder
a capacidade a quem deve tê-la ou corrigir o cliente/manifesto, e então trocar
o modo.

## Segredo por referência

`POST /api/clients` e `PUT /api/clients/{clientId}` aceitam:

```json
{
  "secretReference": { "name": "clients/reports/secret", "contextId": "global" }
}
```

- `name` é o caminho do segredo nomeado no Vault; `contextId` é opcional
  (`global`).
- O serviço resolve o segredo pelo próprio serviço de Vault do Management, com
  a autorização do operador: exige `identity.secrets.resolve` e a concessão do
  namespace, e a resolução fica no diário do Vault. Quem não pode ler o
  segredo não o transforma em credencial.
- O valor é gravado como hash na aplicação e nunca volta na resposta. A
  aplicação guarda só a origem (`identity:management:secret-reference`, por
  exemplo `global:clients/reports/secret`).
- Na criação, a referência torna a aplicação confidencial. Na edição, troca o
  segredo de uma aplicação confidencial; `null` mantém o segredo atual.
- Erros: `client_secret_reference_not_found`, `client_secret_reference_expired`,
  `client_secret_reference_invalid`,
  `client_secret_reference_requires_confidential` (edição de aplicação
  pública), `vault_required` (Vault desligado) e `403` sem capacidade de Vault.

### `clientSecret` em texto claro (obsoleto)

O campo `clientSecret` do `POST /api/clients` continua aceito como adaptador
de compatibilidade, até `Management:ClientSecrets:PlaintextExpiresAtUtc`
(padrão `2027-04-30T00:00:00Z`):

- antes da data: aceito, com log de aviso e linha de auditoria
  `client_secret_plaintext_deprecated` (`operationOutcome=warning`, sem nome
  ou e-mail do operador e sem o segredo);
- a partir da data: `400 client_secret_plaintext_expired`, também auditado;
- `clientSecret` e `secretReference` juntos: `400 client_secret_source_ambiguous`.

Para achar quem ainda usa o adaptador: linhas com
`reasonCode = 'client_secret_plaintext_deprecated'`. O segredo gerado pelo
servidor no assistente de criação e a rotação (`/secret/rotate`) não passam
por este adaptador.
