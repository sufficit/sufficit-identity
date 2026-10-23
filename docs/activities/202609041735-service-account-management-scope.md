# Contas de serviço recebem o escopo `identity.management`

## Objetivo

Permitir que um serviço consumidor resolva referências de segredos no Vault do
Identity com `client_credentials`, sem colocar `client_secret` no repositório
ou no `appsettings.json` publicado.

## Alteração

- A criação de contas de serviço passou a atribuir o escopo reservado
  `identity.management` junto das permissões fixas do fluxo
  `client_credentials`. A capacidade efetiva continua limitada pelo papel da
  conta e pelo mapa de Vault da implantação.
- A credencial do serviço consumidor fica fora do release (por exemplo, num
  arquivo de ambiente do systemd com permissão restrita).

## Validação

- Testes de criação de conta: 6 aprovados.
- Token `client_credentials` com `identity.management`: HTTP 200.
- Resolução de um segredo no contexto do serviço consumidor: HTTP 200, valor
  presente.
