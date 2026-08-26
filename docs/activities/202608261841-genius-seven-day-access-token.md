# Genius: access token de sete dias

Data: 2026-08-26

## Contexto

O cliente público `sufficit-ai-genius` usa Device Authorization Grant com
`offline_access`. O aplicativo armazena o refresh token rotativo e renova o
access token antes da expiração. A política global permanece em 60 minutos e o
refresh token global permanece em 14 dias.

Para reduzir especificamente a frequência de troca do access token no Genius,
sem ampliar os demais clientes, o registro desse cliente recebe um override de
10.080 minutos (sete dias). A alteração vale apenas para tokens emitidos depois
da reconciliação; tokens existentes conservam a expiração original.

## Implementação

- O limite administrável de access tokens passou de 24 horas para sete dias.
- API, rascunhos e UI compartilham o mesmo limite canônico.
- A gestão apresenta valores integrais em horas ou dias, em vez de exibir
  `10080 minutos`.
- O comando local `--reconcile-client-token-lifetimes` aplica somente os
  clientes presentes em `Sufficit:Identity:Tokens:ClientOverrides` e encerra o
  processo sem iniciar HTTP.
- A configuração é consumida apenas nessa execução explícita; inicializações
  normais não revertem futuras alterações feitas pela gestão.

## Segurança

O padrão global curto não mudou. O Genius continua usando refresh token
rotativo e access token de referência, portanto revogação e introspecção
continuam disponíveis. O comando de reconciliação exige acesso local ao host e
às mesmas configurações protegidas do serviço; não foi criado endpoint HTTP de
manutenção.

## Verificação

- Teste de emissão confirma `expires_in` de sete dias no cliente configurado.
- Teste do reconciliador confirma binding da configuração e idempotência.
- Valores acima de 10.080 minutos continuam recusados.
- Suíte completa: 897 testes aprovados, zero avisos.
