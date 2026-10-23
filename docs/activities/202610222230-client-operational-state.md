# Suspender e reativar cliente sem apagar (E1)

**22/10/2026.** Até aqui, a única forma de cortar um cliente OAuth era apagá-lo,
sem volta.

## Modelo

- Estado nas **propriedades do próprio cliente** (`applications.properties`,
  chave `sufficit:disabled` = `{atUtc, by, reason}`); sem a chave, ativo — todo
  cliente existente segue funcionando. Sem tabela nova: auditoria já fica em
  `managementauditevents`, concorrência no `concurrency_token`, e o
  provisionador de manifesto preserva chaves que não gerencia (re-aplicar um
  manifesto não reativa ninguém).
- **Verificação sem consulta por requisição:** `DisabledClientRegistry` (STS)
  mantém o conjunto em memória em cada nó — carregado antes de servir, relido a
  cada 30 s (uma consulta pequena, só linhas com a chave) e na hora quando um nó
  anuncia mudança no Redis (`sufficit:identity:client-state`). Falha de leitura
  mantém o último conjunto conhecido (nunca reativa por acidente).
- **Onde recusa** (`RejectDisabledClient`): authorize, PAR, device authorization,
  token (todos os grants, refresh incluso) e introspecção chamada pelo cliente
  → `unauthorized_client`; e todo token emitido a ele (presenters) →
  `invalid_token`, então access tokens dele falham no userinfo e são
  "inactive" na introspecção. Cada recusa é registrada com o `client_id`.
  JWT validado localmente por um resource server continua até expirar (1 h).
- **Operação** `POST api/clients/state?clientId=…` `{enabled, reason, revokeTokens,
  expectedVersion}` (capability `identity.clients.update`): motivo obrigatório
  ao suspender; opção de revogar tokens e autorizações (sessões não voltam ao
  reativar); auditoria `client_disabled`/`client_enabled` com antes/depois.
  Vale também para cliente de manifesto (estado operacional, não
  configuração).
- **Console:** estado no detalhe, aviso com data/autor/motivo quando suspenso,
  seção "Suspender cliente" com motivo e revogação, "Reativar" com
  confirmação, resultado em toast; filtro "Suspensos" na lista.

O plano previa começar em modo de observação: não se aplica — nenhum cliente
nasce suspenso, a suspensão é sempre um ato explícito de operador.

## Desfazer

Reativar pela console ou API; em último caso, remover a chave
`sufficit:disabled` do `properties` do cliente (os nós releem em até 30 s).
