# Escopo `identity.vault`: Vault pessoal restrito para agentes

Data: 2026-10-13 (UTC). Pedido do dono: o token de canal de um agente (bot
Telegram) fica direto no Vault; ajustar o Vault primeiro.

## Problema

O Vault pessoal (`/api/vault/personal/secrets`) só abria com `identity.mcp`, que
dá o Vault inteiro e todas as ferramentas MCP do Identity. A credencial delegada
de um agente de nuvem (ex.: cliente `example-native-app-executor`) nunca recebe esse
escopo, então o agente não alcançava o Vault.

## Código (`d893adc`)

- Política `sufficit-identity-personal-vault`: aceita `identity.mcp` (Vault
  inteiro, como antes) **ou** `identity.vault`.
- Com só `identity.vault`: lê e grava `app/…` (segredos de dispositivo
  do aplicativo, ex. token do bot de um agente), lê `ai/…` (o que o dono compartilha
  com agentes), não vê nada além disso (lista incluída). Fora disso: 403
  `vault_name_outside_scope`.
- Teste `PersonalVaultNarrowScopeTests`; suíte 1679/1680 verde.

## Produção (2026-10-13 ~20:30Z)

- Release `20261013T202739Z-d893adc` nos 3 nós (uniforme).
- Banco (backup das permissões antes da alteração):
  escopo `identity.vault` criado; `scp:identity.vault` adicionado a
  `example-native-app` e `example-native-app-executor`.
- `appsettings.Production.json` de cada nó (backup `*.bak-vault-scope-*`,
  `root:www-data` preservado): `FirstPartyUserScopes.example-native-app` =
  `["orders.api", "identity.vault"]`; nós reiniciados um a um (app-node-1,
  app-node-2, app-node-3), `/health/ready` 200.

## Efeito

O token do aplicativo do dono passa a carregar `identity.vault` no próximo refresh
(sem novo login); a troca RFC 8693 repassa o escopo à credencial delegada (o
cliente do executor tem a permissão). Credenciais delegadas emitidas antes não
têm o escopo: valem a partir da próxima delegação.

## Revisão 2026-10-14 (`7bd6c48`): Vault pessoal inteiro

Decisão do dono: o agente alcança **tudo** do Vault pessoal do dono, como os aparelhos dele.
`identity.vault` deixou de restringir a `app/` e `ai/`; continua abrindo só a API do Vault
pessoal, nunca o resto do MCP do Identity. Entradas exclusivas de um agente ficam em
`<id do agente>/…` e o aplicativo do dono as apaga ao remover o agente. Release
`20261014T023555Z-7bd6c48` nos 3 nós (configuração herdada).
