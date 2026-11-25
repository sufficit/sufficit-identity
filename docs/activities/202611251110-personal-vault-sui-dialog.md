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

A disponibilidade em produção depende da publicação do código entregue
na branch `main`.
