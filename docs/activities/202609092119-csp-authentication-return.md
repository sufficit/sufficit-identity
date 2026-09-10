# Retorno de autenticação compatível com CSP

**Concluído em:** 2026-09-09

## Objetivo

Permitir que o usuário conclua senha ou MFA e retorne ao Blazor sem ampliar a
política `form-action 'self'` do Identity.

## Estado inicial

Em produção, o POST same-origin para `/account/login/2fa` era processado e o
cookie de autenticação era atualizado. Em seguida, sua resposta redirecionava
para `/connect/authorize`, que finalmente redirecionava ao callback registrado
do Blazor. Navegadores aplicam `form-action` a toda essa cadeia; como o destino
final era outra origem, a CSP em modo enforce bloqueava a navegação.

O primeiro POST consumia corretamente o estado MFA. Uma segunda tentativa
encontrava a conta já autenticada e o `request_uri` PAR parcialmente processado,
produzindo a tela “Você já está autenticado”.

## Alterações

- criado `AuthenticationContinuation`, que transforma apenas um `returnUrl`
  local validado em uma rota intermediária same-origin;
- sucessos de senha, código autenticador e código de recuperação agora encerram
  o POST em `/account/authenticationcontinue`;
- criada uma página de continuação com mensagem acessível e link manual;
- `identity.js`, servido pela própria origem e permitido pela CSP, inicia uma
  nova navegação com `window.location.replace` para o caminho local validado;
- mantida a proteção contra submissões duplicadas dos formulários sensíveis;
- nenhuma origem externa foi adicionada ao `form-action`, e o callback continua
  sendo determinado exclusivamente pelo servidor OIDC após validar o cliente.

## Decisão de segurança

Não foi usada uma allowlist global do domínio do Blazor. Além de não atender a
outros clientes OIDC, isso aumentaria desnecessariamente a capacidade dos
formulários do Identity. Encerrar o POST antes de retomar a autorização separa
as duas navegações e mantém `form-action 'self'` efetivo.

## Validação

- testes direcionados de controladores, reautenticação e arquitetura: **59
  aprovados**, sem warnings;
- suíte completa de Identity: **1.116 aprovados**, sem warnings;
- build Release de `Sufficit.Identity.Server`: **0 erros e 0 warnings**;
- validação sintática de `identity.js` com `node --check`: aprovada;
- `git diff --check`: aprovado.

## Entrega

O commit e a publicação serão registrados abaixo após a conclusão do fluxo de
entrega.
