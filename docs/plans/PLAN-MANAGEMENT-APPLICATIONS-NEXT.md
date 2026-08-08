# Próximo plano — catálogo de capacidades e lista operacional de aplicações

**Status:** pendente
**Plano principal:** [`PLAN-MANAGEMENT-APPLICATIONS.md`](PLAN-MANAGEMENT-APPLICATIONS.md)
**Criado:** 2026-08-08

O catálogo de capacidades e a derivação de perfis foram concluídos e movidos
para [`../activities/202608082230-completed-runtime-capability-catalog.md`](../activities/202608082230-completed-runtime-capability-catalog.md).
Este arquivo mantém somente o trabalho que ainda falta.

## Objetivo

Preparar a lista de aplicações para operação real em produção, sem carregar
todos os registros no circuito e sem perder filtros ao recarregar a página.

## Entregas pendentes

- [ ] Paginar, pesquisar e filtrar aplicações no serviço/API; manter `q`,
  `type`, `grant`, `scope`, `origin`, `status`, `page` e `pageSize` na URL.
- [ ] Transformar a lista em cards rotulados no mobile, preservando uma tabela
  eficiente no desktop.
- [ ] Cobrir catálogo vazio, feature desabilitada, capability negada, filtros
  inválidos e deep links com testes de contrato, integração e UI.

## Limites

- Não alterar grants globais nem habilitar fluxos no runtime.
- Não copiar credenciais, tokens, autorizações ou propriedades de manifesto
  para a lista.
- Não alterar clientes gerenciados por manifesto pela UI manual.

## Critério de conclusão

O configurador mostra somente capacidades realmente habilitadas, a lista não
carrega todos os registros no circuito e a mesma consulta reproduzida pela URL
retorna o mesmo resultado em API e UI.
