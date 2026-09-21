# Cadastro recusado para conta existente

## Objetivo e diagnóstico

Investigar a mensagem de erro de cadastro apresentada na captura do cliente e corrigir a orientação para recuperação de acesso.

A árvore de trabalho estava limpa. A mensagem exibida na captura corresponde exclusivamente aos códigos `DuplicateUserName` e `DuplicateEmail` em `Register.razor`. A configuração de produção usa o e-mail como nome de usuário. Uma consulta restrita ao endereço do incidente, em transação `READ ONLY` no banco configurado do processo de eveo-apps, confirmou uma conta existente, com e-mail confirmado, senha definida, bloqueio expirado e zero falhas acumuladas. Não foram consultados valores de senha/hash nem alterados dados da conta.

O cadastro repetido foi recusado corretamente. A mensagem anterior (“Verifique os dados informados”) não explicava como recuperar o acesso. O CAPTCHA desmarcado na imagem é compatível com o reset que a página executa depois da recusa; não demonstra falha do CAPTCHA.

## Alterações

- `src/ui/Sufficit.Identity.UI/Resources/SharedResource.pt-BR.resx` e `SharedResource.resx`: orientação condicional para entrar/recuperar senha caso o endereço já tenha sido utilizado, ou solicitar confirmação caso ainda não tenha sido confirmado.
- `src/ui/Sufficit.Identity.UI/Pages/Account/Register.razor`: após erro, disponibiliza os links existentes de recuperação de senha e reenvio de confirmação, junto ao link de login.
- `src/tests/PublicAuthenticationBoundaryTests.cs`: cobre cadastro repetido com endereço em caixa diferente para contas confirmadas e não confirmadas; verifica recusa, preservação de identidade/senha/security stamp, descrição sem endereço e recuperação posterior com confirmação quando necessária.

## Decisões

- Preservadas as regras de unicidade e autenticação. Nenhum envio automático de e-mail na recusa e nenhuma alteração do serviço de cadastro.
- A mensagem pública continua sem confirmar explicitamente a existência da conta; os links aparecem após qualquer erro tratado pela página.
- Referência visual: captura recebida, layout vigente e componentes Sufficit.Blazor.UI. Refero `references/copywriting.md` e Impeccable `reference/clarify.md` fundamentam a orientação acionável. Nenhum token, estilo ou componente novo.
- O atendimento desse caso deve encaminhar o cliente para `/account/forgotpassword`, pois a conta já está confirmada.

## Validação

```sh
rtk dotnet test src/tests/Sufficit.Identity.Tests.csproj --no-restore --filter 'FullyQualifiedName~PublicAuthenticationBoundaryTests|FullyQualifiedName~HumanVerificationTests|FullyQualifiedName~UiLocalizationTests|FullyQualifiedName~ManagementUiArchitectureTests|FullyQualifiedName~PasswordResetRevocationTests' --verbosity quiet
```

Resultado: **107 testes aprovados, zero avisos**.

- Detector Impeccable no `Register.razor`: nenhum achado (`[]`).
- `git diff --check`: aprovado.
- Playwright: UI compilada em host local temporário com serviços simulados, sem banco de produção nem envio de e-mail. Conferidos erro de duplicidade em pt-BR/en-US, links para recuperação e confirmação e suas páginas de destino, desktop de 1440 px e celular de 390 px. Sem overflow horizontal na verificação automatizada; screenshots em português inspecionadas.
- Evidências locais temporárias: `/tmp/identity-registration-review/desktop.png`, `/tmp/identity-registration-review/mobile.png` e registros do Playwright na mesma pasta.

O harness precisou entregar o script Blazor original sem compressão, por interceptação local no navegador, devido a erro de decodificação no manifest de assets do host temporário. A cultura foi definida por cookie para manter o idioma do circuito. Uma digitação antecipada à hidratação foi repetida. Essas adaptações não alteram o produto e a verificação visual não substitui um teste de implantação.

## Entrega e limites

Alterações locais, sem commit, push ou publicação. Nenhuma conta real foi criada/modificada e nenhuma mensagem foi enviada ao cliente. O host e o navegador temporários foram encerrados. A orientação no site em produção permanece a anterior até a publicação desta alteração.

O plano temporário desta tarefa foi encerrado neste relatório; não havia referências externas a preservar.
