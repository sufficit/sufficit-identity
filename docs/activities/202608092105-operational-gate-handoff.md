# Handoff dos gates operacionais de produção

**Concluído em:** 2026-08-09
**Escopo:** reconciliação de dependências externas, sem declarar ambientes não
inspecionados como prontos.

## Resultado

As pendências de rollout e comprovação que não podem ser executadas somente no
workspace foram removidas do plano de implementação e transferidas para o plano canônico
[`PLAN-PRODUCTION-READINESS.md`](../plans/PLAN-PRODUCTION-READINESS.md).

Foi criado
[`RUNBOOK-PRODUCTION-EVIDENCE.md`](../runbooks/RUNBOOK-PRODUCTION-EVIDENCE.md)
com procedimento, critérios e formato de prova para:

- remoção de `Observe`, `Audit` e authorization-off em SCIM, token exchange,
  personal tokens, CIBA, credential mutations, origem pública e Management;
- inventário e eliminação de `pt1.` no banco e em estado efêmero;
- Redis e replay/nonce compartilhado entre réplicas;
- CSP, inventário/rotação de certificados, separação KEK/signing e disaster
  recovery;
- conformance e auditoria externa.

## Evidência disponível no repositório

- os defaults versionados estão em `Enforce` para as políticas tratadas;
- o posture check de produção falha fechado e exige acknowledgement com finding
  ID, owner, motivo e expiração;
- não existe configuração de ambiente de produção nem registro de execução dos
  rollouts no workspace;
- o template local mantém exceções próprias de desenvolvimento e não serve como
  prova de produção.

Consequentemente, os gates continuam **abertos** no plano de prontidão até cada
ambiente anexar evidência redigida. O handoff fecha a duplicidade de
planejamento, não presume a conclusão operacional.

## Reconciliações adicionais

- o checklist mTLS agora reconhece a fronteira de trusted proxy, revogação e os
  testes de wrong-client, chain, proxy, conexão direta, expiry e sobreposição de
  certificados;
- o checklist do vault reconhece as implementações certificate/external KEK;
- `ONBOARD.md` não sugere mais que
  `RequireEncryptionInProduction=false` possa desativar o guard.

## Validação

`MtlsPolicyTests`: **13 testes aprovados**, incluindo a sobreposição limitada de
dois pins durante rotação.
