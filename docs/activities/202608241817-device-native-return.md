# 2026-08-24 — Retorno ao cliente nativo no Device Authorization Grant

Issue: [#40](https://github.com/sufficit/sufficit-identity/issues/40).

## Problema

Clientes móveis abrem `/connect/device` em uma aba normal do navegador. Essa
aba não possui `window.opener` e não pode ser fechada por JavaScript; depois da
autorização, a tela terminal só explicava como fechá-la manualmente.

## Entrega

- O fluxo preserva `launch_mode=app` e um `return_uri` somente quando o endereço
  corresponde ao callback fixo `sufficit-genius://auth-complete`.
  > Superado em 2026-08-26: o callback deixou de ser fixo e virou registro por
  > cliente — ver
  > [202608260133-native-return-uris-per-client](202608260133-native-return-uris-per-client.md).
- A página terminal tenta o callback uma vez e mantém **Voltar ao aplicativo**
  como ação primária para navegadores que bloqueiam a abertura automática.
- O callback não recebe código, token, conta ou estado de autorização. O
  cliente continua resgatando credenciais exclusivamente pelo polling RFC 8628.
- URLs arbitrárias, variações do callback e esquemas executáveis são recusados.
- Testes HTTP, unitários, arquiteturais e Playwright cobrem a propagação e o
  fallback.
