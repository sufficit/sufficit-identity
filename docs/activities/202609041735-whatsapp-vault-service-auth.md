# Autenticação do endpoint no Vault para WhatsApp Official

## Objetivo

Permitir que o serviço `sufficit-endpoints` resolva referências de segredos do
Meta no Vault do Identity sem colocar `client_secret` no repositório ou no
`appsettings.json` publicado.

## Alterações

- A criação de contas de serviço passou a atribuir o escopo reservado
  `identity.management` junto das permissões fixas do fluxo
  `client_credentials`.
- O Identity foi publicado no Eveo e reiniciado com sucesso.
- Foi criada uma conta de serviço dedicada para o endpoint, com o papel
  `mobilecloudadministrator` (capacidade efetiva limitada ao mapa de Vault da
  implantação).
- O endpoint Eveo recebeu a credencial por arquivo de ambiente do systemd,
  com permissões `root:dotnetuser`/`0640`; o segredo não é persistido no
  release.

## Validação

- Testes de criação de conta: 6 aprovados.
- Token `client_credentials` com `identity.management`: HTTP 200.
- Resolução de `meta/chat-neuraltalk/client-secret` no contexto
  `sufficit-endpoints`: HTTP 200, valor presente.
- `GET /Gateway/WhatsApp/Official/app` no endpoint Eveo: HTTP 200.
- Serviço `sufficit-identity` e `sufficit-endpoints`: ativos após reinício.

## Observação

O endpoint ainda registra falhas preexistentes de conexão com o banco
`sufficitauth`; elas são independentes da autenticação do Vault e não impedem
o health check nem a resolução do segredo validada acima.
