# Escopo `identity.vault`: Vault pessoal restrito para agentes

Data: 2026-10-13 (UTC). Pedido do dono: o token de canal de um agente (bot
Telegram) fica direto no Vault; ajustar o Vault primeiro.

## Problema

O Vault pessoal (`/api/vault/personal/secrets`) só abria com `identity.mcp`, que
dá o Vault inteiro e todas as ferramentas MCP do Identity. A credencial delegada
de um agente de nuvem (cliente `sufficit-ai-genius-executor`) nunca recebe esse
escopo, então o agente não alcançava o Vault.

## Código (`d893adc`)

- Política `sufficit-identity-personal-vault`: aceita `identity.mcp` (Vault
  inteiro, como antes) **ou** `identity.vault`.
- Com só `identity.vault`: lê e grava `genius/…` (segredos de dispositivo
  Genius, ex. token do bot de um agente), lê `ai/…` (o que o dono compartilha
  com agentes), não vê nada além disso (lista incluída). Fora disso: 403
  `vault_name_outside_scope`.
- Teste `PersonalVaultNarrowScopeTests`; suíte 1679/1680 verde.

## Produção (2026-10-13 ~20:30Z)

- Release `20261013T202739Z-d893adc` nos 3 nós (uniforme).
- Banco (backup `eveo-apps:/root/identity-backups/vault-scope-permissions-20261013T202915Z.tsv`):
  escopo `identity.vault` criado; `scp:identity.vault` adicionado a
  `sufficit-ai-genius` e `sufficit-ai-genius-executor`.
- `appsettings.Production.json` de cada nó (backup `*.bak-vault-scope-*`,
  `root:www-data` preservado): `FirstPartyUserScopes.sufficit-ai-genius` =
  `["fleet.api", "identity.vault"]`; nós reiniciados um a um (castrum, apoint,
  eveo), `/health/ready` 200.

## Efeito

O token do Genius do dono passa a carregar `identity.vault` no próximo refresh
(sem novo login); a troca RFC 8693 repassa o escopo à credencial delegada (o
cliente do executor tem a permissão). Credenciais delegadas emitidas antes não
têm o escopo: valem a partir da próxima delegação.

## Revisão 2026-10-14 (`7bd6c48`): Vault pessoal inteiro

Decisão do dono: o agente alcança **tudo** do Vault pessoal do dono, como os aparelhos dele.
`identity.vault` deixou de restringir a `genius/` e `ai/`; continua abrindo só a API do Vault
pessoal, nunca o resto do MCP do Identity. Entradas exclusivas de um agente ficam em
`<id do agente>/…` e o Genius do dono as apaga ao remover o agente. Release
`20261014T023555Z-7bd6c48` nos 3 nós (configuração herdada).
