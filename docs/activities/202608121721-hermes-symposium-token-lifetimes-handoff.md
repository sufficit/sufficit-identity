# Hermes e Symposium — política de validade dos tokens

Data do checkpoint: 2026-08-12 17:21:59 -03  
Estado: pausado a pedido do operador para priorizar a central de tokens do Management.

## Solicitação registrada

- Manter no cliente `hermes` a política de refresh token adequada à integração
  do plugin Hermes, com renovação por refresh token em vez de access token de
  longa duração.
- Aplicar a mesma política ao cliente correspondente ao próprio Hermes, desde
  que ele seja identificado sem ambiguidade.
- Configurar o cliente `sufficit-vscode-symposium` com refresh token de 7 dias.
- Não manter o nome legado ChatRoot onde o recurso representar o Hermes.

## Inventário confirmado em produção

Leitura realizada no banco canônico `identity`, sem mutação:

| Client ID | Nome exibido | Tipo | Fluxos relevantes | Segredo |
| --- | --- | --- | --- | --- |
| `hermes` | Hermes Sufficit Plugin | public | Authorization Code + Refresh Token + PKCE | não |
| `sufficit-hermes-n8n` | Sufficit Hermes N8N | confidential | Client Credentials | sim |
| `sufficit-vscode-symposium` | Sufficit VSCode Symposium | public | Authorization Code + Device Code + Refresh Token + PKCE | não |

Não existe cliente com `client_id` ou nome exibido `ChatRoot` no ambiente
consultado. O cliente `sufficit-hermes-n8n` não recebe refresh token porque usa
somente Client Credentials; portanto ele não deve receber uma configuração de
refresh token sem que seu fluxo OAuth também seja alterado de forma explícita.

## Política global observada

- Access token: 60 minutos.
- ID token: 20 minutos.
- Refresh token: 14 dias.
- Refresh tokens são rotativos e a validade é deslizante enquanto a renovação
  continua dentro da política do OpenIddict.

Os registros migrados ainda carregam chaves legadas em `settings`, incluindo
`absolute_refresh_token_lifetime` e `sliding_refresh_token_lifetime`. A tela e o
serviço atuais usam as chaves canônicas de token lifetime do OpenIddict; uma
alteração operacional deve passar pelo serviço de Management, não por SQL.

## Alteração pretendida ao retomar

1. Confirmar se “próprio Hermes” significa outro cliente além de `hermes`. O
   inventário atual só encontrou `hermes` e o cliente técnico
   `sufficit-hermes-n8n`, que não utiliza refresh token.
2. Definir em `hermes` o refresh token explicitamente em 14 dias, preservando
   access token em 60 minutos e ID token em 20 minutos, se a intenção for fixar
   os valores atuais por cliente em vez de herdar o padrão global.
3. Definir em `sufficit-vscode-symposium` o refresh token em 7 dias, preservando
   access token em 60 minutos e ID token em 20 minutos.
4. Executar a atualização pelo endpoint canônico de clientes com sessão MFA e
   capability `identity.clients.update`.
5. Ler novamente os dois clientes, confirmar os valores efetivos e registrar a
   auditoria/correlation ID. A configuração está no banco compartilhado; não há
   uma alteração distinta por nó, mas os três nós devem ser consultados para
   confirmar que leem o mesmo estado.

## Credenciais e limites operacionais

- O token temporário de provisioning possui somente
  `identity.provisioning.preview` e `identity.provisioning.apply`; ele não
  autoriza `/api/clients/{clientId}`.
- A atualização direta de clientes exige `identity.clients.update`, MFA e o
  escopo de Management.
- Nenhum segredo foi copiado para este documento.

