# Próximo plano — operação e escala da lista de aplicações

**Status:** pendente
**Plano principal:** [`PLAN-MANAGEMENT-APPLICATIONS.md`](PLAN-MANAGEMENT-APPLICATIONS.md)
**Criado:** 2026-08-08

O catálogo de capacidades, a derivação de perfis e a primeira entrega da lista
operacional foram concluídos e movidos para:

- [`../activities/202608082230-completed-runtime-capability-catalog.md`](../activities/202608082230-completed-runtime-capability-catalog.md)
- [`../activities/202608082300-completed-client-catalog-pagination.md`](../activities/202608082300-completed-client-catalog-pagination.md)
- [`../activities/202608082330-completed-client-empty-deep-link.md`](../activities/202608082330-completed-client-empty-deep-link.md)

Este arquivo mantém somente o trabalho que ainda falta.

## Objetivo

Completar a operação da lista de aplicações e preparar a evolução do ciclo de
vida sem inventar um estado de ativação que o runtime ainda não aplica.

## Entregas pendentes

- [ ] Fazer inspeção visual em 320, 360, 390 e 430 px, incluindo teclado,
  foco, filtros empilhados e paginação.
- [ ] Definir o modelo de estado operacional antes de expor filtros além de
  `active`; a entidade OpenIddict atual não possui habilitação/desabilitação.

## Limites

- Não alterar grants globais nem habilitar fluxos no runtime.
- Não copiar credenciais, tokens, autorizações ou propriedades de manifesto
  para a lista.
- Não alterar clientes gerenciados por manifesto pela UI manual.

## Critério de conclusão

O catálogo e a lista não carregam todos os registros no circuito, a mesma
consulta reproduzida pela URL retorna o mesmo resultado em API e UI e nenhum
estado operacional é exibido sem enforcement correspondente.
