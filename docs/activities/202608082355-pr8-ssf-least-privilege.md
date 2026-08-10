# Atividade concluída — PR #8: streams SSF com privilégio mínimo

> **Concluída em:** 2026-08-08 · **PR:** #8

## Entrega

- `events_requested` ausente ou vazio é rejeitado sem modo legado ambíguo.
- O matcher permanece fail-closed para dados vazios ou malformados já persistidos.
- A exigência opcional de sujeito explícito foi adicionada ao template e ao runbook.
- O runbook documenta o impacto e a recriação de streams antigos.
- Testes cobrem rejeição na criação, matching e política de sujeito.

## Validação

- Build Release com `-warnaserror`: 14 projetos, nenhum erro ou warning.
- Suíte completa: 552 testes aprovados.
