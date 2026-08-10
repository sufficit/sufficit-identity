# Atividade concluída — catálogo paginado de aplicações

**Data:** 2026-08-08  
**Status:** concluída, testada e validada  
**Plano:** [`../plans/PLAN-MANAGEMENT-APPLICATIONS-NEXT.md`](../plans/PLAN-MANAGEMENT-APPLICATIONS-NEXT.md)

## Entrega

- A Management API ganhou `ManagementClientQuery` e `ManagementClientPage`.
- A consulta é paginada no servidor, com limite máximo de 100 itens por página.
- Foram adicionados filtros por busca, tipo, grant, scope e origem (manual ou
  manifesto), sem carregar o catálogo inteiro no circuito.
- A UI preserva `q`, `type`, `grant`, `scope`, `origin`, `status`, `page` e
  `pageSize` na URL; alterações de filtro retornam à primeira página.
- A lista mantém tabela eficiente no desktop e linhas rotuladas/responsivas no
  mobile.
- O filtro de estado aceita apenas `all` e `active` enquanto não existir
  enforcement de bloqueio/revogação na entidade OpenIddict; nenhum estado
  fictício foi exposto.

## Validação

- `dotnet build src/tests/Sufficit.Identity.Tests.csproj --no-restore`
- `dotnet test src/tests/Sufficit.Identity.Tests.csproj --no-build`
- Resultado: build sem erros; 528 testes aprovados e 1 teste de localização
  ignorado.
- O detector visual foi executado; os avisos de fonte Inter e da borda de
  navegação lateral já existiam antes desta entrega.

## Próximo limite

Permanece pendente a inspeção visual nos breakpoints móveis, a cobertura de
estados vazios/deep links e a definição de um estado operacional real antes de
oferecer filtros além de `active`.
