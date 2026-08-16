# Identity MCP — Vault e self-service

## Entrega

O módulo opcional de Management agora registra um transporte MCP
streamable-HTTP em `/api/mcp`, com JSON-RPC para `initialize`, `ping`,
`tools/list`, `tools/call` e notificações de inicialização.

O endpoint exige Bearer autenticado e cria sessões de transporte de curta
duração. Cada sessão é vinculada ao `sub` do access token, impedindo que um
`mcp-session-id` seja reutilizado por outra conta.

## Ferramentas

- Vault: `vault_list`, `vault_get_info`, `vault_save`, `vault_delete` e
  `vault_resolve`.
- Self-service: `me_get`, `me_update`, `me_sessions_list`,
  `me_session_revoke`, `me_authorizations_list` e
  `me_authorization_revoke`.

O contexto pessoal é `user-<sub>`. Contextos explícitos continuam sujeitos às
capabilities de Vault. `vault_resolve` exige confirmação explícita de texto
claro e audita cada tentativa; ferramentas de perfil não expõem troca de
senha, e-mail ou MFA.

## Validação

Os testes de contrato cobrem autenticação, handshake, vínculo da sessão,
listagem das ferramentas e execução de `me_get`. A documentação de consumo
está em [USAGE-IDENTITY-MCP.md](../usage/USAGE-IDENTITY-MCP.md).
