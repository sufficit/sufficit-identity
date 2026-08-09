# Atividade concluída — PR #9: revogação após redefinição de senha

> **Concluída em:** 2026-08-08 · **PR:** #9

## Entrega

- A redefinição de senha revoga tokens, autorizações e sessões do navegador.
- A verificação usa um novo escopo EF e observa o estado persistido após bulk update.
- O teste cria e valida um refresh token real e uma sessão de navegador.
- O evento CAEP de alteração de senha é emitido independentemente da revogação local.
- Falhas transitórias de revogação recebem três tentativas limitadas, métrica e log crítico.
- O resultado permanece correto quando a senha já foi alterada, mesmo se a limpeza esgotar as tentativas.

## Validação

- Build Release com `-warnaserror`: 14 projetos, nenhum erro ou warning.
- Suíte completa: 547 testes aprovados.
