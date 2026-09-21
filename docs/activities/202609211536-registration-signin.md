# Continuação de cadastro para login e vinculação externa comprovada

## Objetivo e estado inicial

Continuar a investigação registrada em `202609211513-registration-failure.md` conforme o fluxo solicitado: uma pessoa que tenta cadastrar uma conta existente deve entrar com as credenciais que já forneceu; senha incorreta deve levar ao login com e-mail preenchido e senha vazia. Uma identidade externa que comprova o mesmo e-mail deve vincular a conta e continuar a autenticação.

O trabalho começou com as alterações locais do diagnóstico anterior. Elas foram preservadas e adaptadas ao novo comportamento. Não houve commit, push, publicação, alteração de conta real ou envio de e-mail.

## Comportamento entregue

| Situação | Resultado |
| --- | --- |
| E-mail ainda não cadastrado | Cadastro e confirmação existentes |
| E-mail existente, senha correta | Login normal e continuação ao destino original |
| Senha incorreta | Login com e-mail preenchido, senha vazia e mensagem de senha |
| Conta sem senha local | Login com aviso informativo de acesso externo/recuperação, sem erro de senha nem incremento do contador de falhas |
| Conta com MFA | Desafio de segundo fator normal |
| Conta bloqueada ou não confirmada | Restrição mantida |
| Provedor comprova e-mail de conta local confirmada | Vincula e continua o login, respeitando MFA/bloqueio |
| Provedor sem prova, negado, conta não confirmada ou endereço ambíguo | Não vincula automaticamente |
| Identidade externa já vinculada cujo e-mail mudou | Continua identificando sua conta original; não transfere o vínculo |

## Alterações por área

- **Cadastro:** `AccountRegistrationResult.RequiresSignIn` sinaliza conta existente. O serviço resolve e-mail único antes de aplicar regras de senha nova e reavalia colisões concorrentes. Não troca senha nem dispara confirmação nessa continuação.
- **Transporte:** `Register.razor` usa helper em `identity.js` para um POST normal em `/account/login/password`, com antiforgery e credenciais no corpo. Cookies são emitidos pela resposta HTTP, nunca pelo circuito Blazor. Nenhuma senha vai para URL, logs ou armazenamento do navegador.
- **Login:** `PasswordSignInCommand.UseEmail` resolve exclusivamente por e-mail único no fluxo proveniente do cadastro, sem fallback para nome de usuário conflitante. O controlador preserva o retorno seguro e entrega somente `login_hint` na falha. A UI preenche e-mail, deixa senha vazia e apresenta aviso neutro quando não há senha local.
- **Vinculação externa:** `AspNetCoreIdentityExternalSignInService` avalia prova do e-mail antes de vincular conta existente, exige confirmação local e política de login, preserva conflitos de vínculo e reutiliza o mesmo caminho de cookie/MFA das identidades já vinculadas. Desativar novos cadastros não impede vincular/acessar conta existente comprovada.
- **Política:** `ExternalIdentityAssertion.ExistingAccount` impede que `RequireVerifiedEmail=false` dispense prova para tomar uma conta já existente. As listas de provedores confiáveis/negados continuam vigentes.
- **Adaptadores:** `GoogleEmailProof` exige prova Gmail/Workspace; removido o uso da marca de perfil `verified` do Facebook como se fosse confirmação do endereço de e-mail.
- **Documentação:** atualizado `docs/runbooks/RUNBOOK-CONFIRMED-EMAIL.md`.

## Decisões e referências

O Google diferencia endereço sob sua autoridade de endereço de terceiros cuja verificação pode ser histórica. O adaptador aceita `email_verified=true` com Gmail ou domínio hospedado `hd`, conforme a [documentação oficial](https://developers.google.com/identity/sign-in/web/backend-auth). Não basta comparar duas strings de e-mail.

Contas locais ainda não confirmadas não são ativadas automaticamente por esse caminho, evitando dar validade a credenciais de um cadastro prévio não comprovado. MFA não é dispensado pela vinculação. Um provedor explicitamente confiável pode comprovar endereços por política do operador; não foi alterada configuração de produção.

Interface preserva layout/componentes SUI. Referência: telas vigentes, captura inicial e diretrizes de conteúdo Refero/Impeccable já consultadas. O aviso de conta sem senha usa o estado informativo existente (`role=status`), sem criar visual de erro.

## Validação

Suíte ampliada:

```sh
rtk dotnet test src/tests/Sufficit.Identity.Tests.csproj --no-restore --filter 'FullyQualifiedName~RegistrationSignInTests|FullyQualifiedName~VerifiedExternalSignInTests|FullyQualifiedName~PublicAuthenticationBoundaryTests|FullyQualifiedName~PasswordLoginControllerTests|FullyQualifiedName~ExternalIdentityLinkingTests|FullyQualifiedName~InteractiveSignInServiceTests|FullyQualifiedName~RememberedSecondFactorTests|FullyQualifiedName~AccountExternalIdentityServiceTests|FullyQualifiedName~HumanVerificationTests|FullyQualifiedName~UiLocalizationTests|FullyQualifiedName~ManagementUiArchitectureTests|FullyQualifiedName~IdentityRateLimitPolicyTests|FullyQualifiedName~SourceFileSizeContractTests' --verbosity quiet
```

**202 testes aprovados, zero avisos.** Após separar o aviso de conta sem senha local, reexecutados `RegistrationSignInTests`, `InteractiveSignInServiceTests`, `PasswordLoginControllerTests` e `UiLocalizationTests`: **35 aprovados, zero avisos**. Os números incluem sobreposição, não representam testes distintos somados.

- Novos testes: cookie por HTTP, senha correta/incorreta, sem senha, MFA, bloqueio/confirmação, preservação de hash, endereço com caixa diferente, colisão de username, retorno externo recusado, prova de provedor, políticas confiável/negada, cadastro desativado, vínculo já existente e autoridade do Google.
- Playwright em host temporário com componentes/controlador reais e serviços simulados: cadastro executa POST com antiforgery; senha correta chega ao destino; erro preenche somente o e-mail; conta sem senha mostra informação e provedor disponível; desktop 1440 px e celular 390 px sem overflow. Nenhum erro JavaScript nos cenários concluídos.
- Screenshots inspecionadas: `/tmp/identity-registration-review/signin-desktop.png`, `signin-mobile.png` e `signin-external-mobile.png`. Scripts locais `check-signin.cjs` e `check-external.cjs` na mesma pasta.
- O harness serviu os arquivos originais de Blazor e `identity.js` por interceptação local para contornar a combinação de manifests/artefatos comprimidos do host temporário. O teste de aviso inicialmente buscou `role=alert`; corrigido para `role=status`, sem mudança no produto.
- `node --check src/ui/Sufficit.Identity.UI/wwwroot/js/identity.js`, detector Impeccable nas páginas e `git diff --check`: aprovados.

## Entrega e limites

Código local validado; não publicado. OAuth real com Google/Facebook não foi executado: os testes de vinculação usam estado externo protegido pelo framework em banco SQLite isolado, e a UI usa serviços simulados. O host temporário e os navegadores foram encerrados. A documentação operacional contém o contrato permanente; o plano temporário foi encerrado neste relatório, sem referências externas pendentes.
