# Confirmação de autenticação recente no fluxo OIDC

**Concluído em:** 2026-09-09

## Problema

Ao selecionar `Confirmar acesso` na página de tokens pessoais, o Blazor
removia o ticket local e iniciava uma nova autorização OIDC. O pedido enviava
`max_age`, mas o Identity aceitava imediatamente seu cookie central antigo sem
avaliar a idade indicada por `auth_time`. O navegador retornava à mesma página
com a mesma evidência antiga e o aviso reaparecia, dando a impressão de que o
botão apenas recarregava a tela.

## Solução

- o Blazor passou a declarar uma única janela de autenticação recente de 15
  minutos, compartilhada entre a pré-validação da tela e o pedido OIDC;
- o endpoint de autorização do Identity agora compara `max_age` exclusivamente
  com `auth_time`, sem usar emissão ou renovação de token como fallback;
- uma sessão antiga interativa é encaminhada para uma cerimônia de
  reautenticação que preserva a conta selecionada e inicia o fluxo TOTP já
  existente;
- a lembrança de navegador confiável é removida antes da cerimônia, evitando
  que ela satisfaça silenciosamente uma exigência de autenticação recente;
- após o código TOTP correto, o Identity emite novo cookie central com
  `auth_time` e evidências MFA atuais e retoma o mesmo pedido OIDC/PAR;
- pedidos com `prompt=none` continuam sem interface e recebem
  `login_required` quando a sessão não é recente;
- usuários sem MFA disponível retornam ao login primário, em vez de obter uma
  autorização aparentemente recente sem nova verificação.

## Testes e validação

- 11 testes da política e integração de reautenticação passaram, incluindo o
  ciclo completo sessão antiga → TOTP → retomada de PAR → código de autorização;
- 17 testes focados do serviço de login interativo e da reautenticação passaram;
- 30 testes focados do fluxo de autenticação e pré-validação do Blazor passaram;
- build Release do `Sufficit.Identity.Server`: 0 warnings e 0 erros;
- build Release do `Sufficit.Blazor.Server`: 0 warnings e 0 erros;
- `git diff --check` não encontrou erros de whitespace.

## Entrega

As alterações ficaram locais e sem commit, push ou deploy. Essas operações
exigem autorização operacional específica.
