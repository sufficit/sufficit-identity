# Formato de access token por cliente e recurso

> **Status:** COMPLETED em 2026-08-09. Entrega correspondente ao item P2.2 de
> `PLAN-CLAUDE-FABLE-5-REMAINING.md` e ao item residual de arquitetura em
> `PLAN-GPT-5-REMAINING.md`.

## Resultado

- `AccessTokenFormatsByClient` permite migrar um `client_id` exato para
  `Jwt` ou `Reference` sem alterar os demais clientes.
- `AccessTokenFormatsByResource` tem precedência para que o contrato do
  resource server determine o formato. Se um token pedir recursos mapeados
  para formatos diferentes, a emissão falha fechada com `invalid_target`.
- `UseReferenceAccessTokens` permanece como fallback compatível para clientes e
  recursos ainda não inventariados; o default histórico continua `true`.
- A infraestrutura OpenIddict mantém os dois pipelines ativos. Uma regra `Jwt`
  produz JWS assinado autocontido, sem a credencial de JWE privada do servidor,
  permitindo validação pelo JWKS público. Tokens pessoais gerados pelo fluxo de
  baixo nível preservam sua decisão explícita de referência.
- Startup limita os mapas a 4.096 entradas exatas e rejeita chaves vazias,
  excessivas ou não normalizadas.

## Rollout

Migre primeiro um resource server, valide assinatura/audience/lifetime e então
cadastre sua regra por recurso. Use regra por cliente somente quando o cliente
não compartilha tokens entre APIs com contratos distintos. Remova a regra de
rollback para retornar ao fallback global; tokens já emitidos mantêm seu
formato e lifetime original.

## Validação

- Testes focados de política, integração client-credentials e personal tokens:
  10 aprovados, 0 warnings.
- O teste de integração confirma JWS com três segmentos e introspecção ativa do
  mesmo JWT.
