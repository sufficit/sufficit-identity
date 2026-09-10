# Retorno ao aplicativo após MFA — prevenção de envio duplicado

**Concluído em:** 2026-09-09

## Sintoma

Depois de confirmar o segundo fator, o navegador exibia uma página do Identity
informando que o acesso não poderia continuar e orientava o usuário a voltar ao
aplicativo, mas sem oferecer um destino de retorno.

## Diagnóstico

Os logs correlacionados do Identity, do proxy e do Blazor mostraram esta
sequência:

1. o pedido OIDC do `SufficitBlazorServer` exigiu autenticação recente;
2. o Identity iniciou a cerimônia MFA preservando o `returnUrl` local;
3. o primeiro POST para `/account/login/2fa` foi aceito às 18:45:38 e retomou
   `/connect/authorize` com sucesso;
4. três segundos depois, o navegador enviou o mesmo formulário novamente;
5. o segundo POST encontrou o estado MFA já consumido e a nova tentativa
   reutilizou o `request_uri` PAR, que também é descartável;
6. a repetição terminou no erro de autorização sem um redirect confiável que o
   Identity pudesse expor na interface.

Portanto, o destino do Blazor não foi perdido no primeiro fluxo. A tela sem
destino pertencia ao segundo envio inválido. Não é seguro reconstruir ou
refletir um `redirect_uri` a partir de parâmetros já consumidos, pois isso
abriria espaço para redirecionamento indevido.

Também foi registrada uma violação de `form-action`. Embora o valor padrão da
aplicação seja report-only, uma verificação posterior no navegador confirmou
que produção está em modo enforce e bloqueia a cadeia de redirecionamentos do
POST. A proteção contra envio duplicado continua necessária, mas não resolve
isoladamente esse bloqueio; a continuação compatível com CSP está documentada
em `202609092119-csp-authentication-return.md`.

## Correção

- os formulários de senha, autenticador e código de recuperação agora declaram
  `data-auth-submit-once`;
- `identity.js` marca o primeiro envio imediatamente e cancela qualquer envio
  posterior enquanto a navegação estiver em andamento;
- os botões são desabilitados somente no próximo ciclo da fila do navegador,
  preservando o submitter e todo o corpo do primeiro POST;
- o estado visual é restaurado no evento `pageshow`, inclusive quando o usuário
  volta a uma página preservada pelo cache de navegação;
- o comportamento foi centralizado para manter os três fluxos de autenticação
  consistentes.

## Validação

- testes direcionados de arquitetura e reautenticação: **56 aprovados**;
- suíte completa de Identity: **1.116 aprovados**, sem warnings;
- build Release de `Sufficit.Identity.Server`: **0 erros e 0 warnings**;
- validação sintática de `identity.js` com `node --check`: aprovada.

## Entrega

Alterações mantidas localmente. Nenhum commit, push ou deploy foi realizado
nesta atividade porque a solicitação atual foi de diagnóstico/correção, sem
nova autorização de publicação.
