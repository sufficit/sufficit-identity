# Diálogo SUI do Vault pessoal

A janela do Vault usa `SUIDialogHost` com o serviço de diálogos da biblioteca.
O código do autenticador usa `SUITextField`, com teclado numérico, preenchimento
de código de uso único e validação de seis dígitos. Os botões SUI ficam juntos
no rodapé. O host da biblioteca gerencia Escape e a devolução do foco.

O diálogo abre após a renderização interativa. A renderização inicial
continua entregando o token de antifalsificação. O campo desativa os eventos
do circuito Blazor. O JavaScript lê o código do formulário e o envia apenas
pelo POST protegido. O valor retornado fica no navegador e é limpo ao fechar,
ao sair da página ou ao expirar a autorização. O prazo de 15 minutos continua
sendo validado pelo [fluxo publicado](202611250956-personal-vault-reveal.md).

## Validação

- Chromium em desktop e celular com dados fictícios. Foram verificados o
  foco no campo, código inválido, confirmação com Enter, leitura, reutilização
  da autorização, expiração, Escape e retorno do foco. A captura do tráfego
  confirmou os códigos no POST e a ausência deles nos frames do circuito.
- Build Release dos 18 projetos e imagem Docker com CSS e módulo de
  diálogo presentes. Suíte principal com 2.187 testes aprovados e dois
  testes da cadeia MFA em Chromium.
- Verificações de documentação, JavaScript, cobertura de migrações,
  hashes de pacotes e auditoria de dependências executadas localmente.

## Publicação e limpeza

A revisão `1694bfb8da42460c944971dad483007a63232c66` já estava na
`main` remota. A release `20261125T141232Z-1694bfb` foi ativada em
sequência nos três nós pelo
[runbook de publicação gradual](../runbooks/RUNBOOK-CLUSTER-ROLLING-DEPLOY.md).
O SHA-256 do pacote foi
`72c32c902a8253c7caeca917b897cd86a1a495b35ec1a5eafd54571597d58105`.
A preparação herdou os quatro arquivos de configuração da release
`20261125T135939Z-facea97`, preservada para rollback. A revisão dispensou
migração de banco.

Os três nós ficaram saudáveis na mesma revisão, com hashes uniformes de
certificado e JWKS iguais aos da checagem inicial. Durante a reinicialização,
sondas diretas receberam HTTP 502 e os nós recuperaram a saúde no prazo do
wrapper. Saúde, prontidão e descoberta OIDC responderam HTTP 200 no endereço
público. Sem sessão, as rotas de página e revelação redirecionaram para o login.
O CSS, o JavaScript do Vault e o módulo do diálogo SUI servidos em produção
coincidiram byte a byte com a revisão e o pacote de origem. O teste autenticado
do 2FA foi feito em ambiente local, com dados fictícios.

A worktree auxiliar, 43 caminhos temporários locais e as três imagens Docker
de validação desta atividade foram removidos. As capturas entregues
permaneceram disponíveis.
