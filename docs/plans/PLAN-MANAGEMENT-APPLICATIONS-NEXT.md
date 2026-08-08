# Próximo plano — catálogo de capacidades e lista operacional de aplicações

**Status:** pendente
**Plano principal:** [`PLAN-MANAGEMENT-APPLICATIONS.md`](PLAN-MANAGEMENT-APPLICATIONS.md)
**Criado:** 2026-08-08

## Objetivo

Remover defaults estáticos da entrada do configurador e preparar a lista de
aplicações para operação real em produção, sem prometer no wizard um fluxo que
o runtime não habilita.

## Entregas pendentes

- [ ] Criar um catálogo de capacidades do runtime (grants, PAR, device flow,
  token exchange e scopes disponíveis) atrás de contrato de aplicação.
- [ ] Derivar os perfis do wizard desse catálogo, informando quando um perfil
  está indisponível e por quê.
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
