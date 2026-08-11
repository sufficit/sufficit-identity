# Management — contexto explícito e retorno ao Enforce

**Data:** 2026-08-11 03:45 (America/Sao_Paulo)  
**Escopo:** operadores do Management embedded e API administrativa

## Motivo

O modo `Observe` havia sido ativado como compatibilidade temporária porque a
sessão administrativa não carregava `identity_context=global`. Isso mantinha o
console acessível, mas deixava a fronteira de contexto apenas observacional.

## Implementação

- O host Sufficit registra `SufficitManagementContextClaimsTransformation`.
- A transformação usa o mesmo `IManagementEntitlementResolver` que autoriza o
  Management; autenticação ou o escopo OAuth isoladamente nunca recebem o
  contexto.
- Quando não existe contexto explícito, um operador com capability de
  Management recebe `identity_context=global` no principal autenticado.
- Um contexto diferente de `global` nunca é sobrescrito automaticamente.
- A ausência de capability continua sem contexto e é negada pelo objeto.
- A configuração persistente dos três nós voltou a
  `ObjectAccess:Mode=Enforce`; o acknowledgment de `Observe` foi removido.

## Validação

- Build Release com warnings tratados como erros: aprovado.
- Suíte completa: 634 aprovados, 1 teste de localização ignorado.
- Testes específicos cobrem operador autorizado, escopo sem capability,
  contexto de outro tenant e principal anônimo.

O contexto global é uma decisão do deployment single-context. Quando houver
organizações/tenants reais, o host deverá emitir o contexto concreto de cada
operador (ou negar a sessão), mantendo `Enforce` sem fallback global.
