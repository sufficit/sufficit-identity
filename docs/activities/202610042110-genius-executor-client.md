# Cliente `sufficit-ai-genius-executor` e escopo de delegação

Fase 5 de `sufficit-ai-genius/docs/PLAN-REMOTE-SESSIONS-KUBERNETES.md`: executor
Genius no Sufficit Run com credencial própria, sem o usuário autorizar cada
ambiente. Registros feitos em produção em 2026-10-04 pela API de Management,
com token temporário de operador (1 h; clientes e escopos: ler, criar, editar).

## Registrado

- Escopo `genius.executor.delegate` (`62b9497d-cc35-4bb2-b5a4-d06b4b1996e4`),
  sem recurso. Marcador de permissão: só o cliente `sufficit-ai-genius` poderá
  pedi-lo, numa troca RFC 8693 que emite credencial do executor.
- Cliente `sufficit-ai-genius-executor`: público, consentimento explícito,
  `refresh_token` + `device_code` (reserva), escopos `openid profile email
  offline_access roles entitlements ai.bridge sufficit_ai_openai_bridge
  fleet.api` — sem `identity.mcp` nem `directives`. Access token 60 min,
  refresh 30 dias.

## Ainda inerte, por decisão

`sufficit-ai-genius` **não** recebeu `gt:token-exchange` nem
`scp:genius.executor.delegate`. Isso entra junto com o código que aplica as
regras da troca: `requested_token_type=refresh_token` emitido ao cliente do
executor, preso ao `jkt` informado (DPoP), escopo reduzido, login recente,
teto por conta, aviso por emissão e revogação no retire/purge do executor.
Sem esse código, conceder a permissão abriria a troca genérica atual.
