# Single-source UI architecture

> Decisão confirmada e refinada em 2026-07-29.
>
> Este é o documento canônico para a fronteira entre as interfaces e o
> domínio do Sufficit Identity. A camada de aplicação é a única fonte de
> verdade em runtime; a API HTTP é um de seus adaptadores.

## Regra

Toda informação operacional exibida ou alterada por uma UI deve passar pelo
mesmo contrato de aplicação usado pelos controllers da API. Isso vale para a
UI pública, a área de autoatendimento e a Management UI.

Uma Razor Class Library incorporada ao mesmo processo pode resolver esses
use cases por DI. Ela não precisa fazer uma chamada HTTP ao próprio host.
O requisito é reutilizar a mesma implementação, validação, autorização e DTO,
sem criar um caminho paralelo.

A UI nunca acessa diretamente banco, `DbContext`, `UserManager`,
`SignInManager`, gerenciadores do OpenIddict ou SDKs de infraestrutura.

## Responsabilidades

A camada de aplicação é proprietária de:

- dados de usuários, clientes, scopes, grants, sessões, branding e auditoria;
- identidade do operador e capabilities efetivas;
- escopo de tenant/contexto e exigências de MFA;
- opções, estados, regras de validação e defaults de negócio;
- paginação, filtros autorizados e resultados de comandos;
- códigos estáveis de erro, autorização e recuperação;
- contratos consumidos por todos os adaptadores.

A UI é proprietária somente de:

- composição visual, acessibilidade e comportamento de apresentação;
- strings estritamente visuais e localização;
- estado transitório de interação, como campo em edição e painel aberto;
- adaptação responsiva dos DTOs recebidos;
- escolha de quais ações apresentar a partir das capabilities retornadas pelo
  use case canônico.

A UI não mantém uma segunda matriz de roles/capabilities, lista de opções de
negócio, regra de tenant, default de segurança ou cópia autoritativa de um
recurso.

## Adaptadores permitidos

```text
UI incorporada
   │ DI
   ▼
contrato/use case de aplicação ◄── controller da API ◄── HTTP/bearer
   │
   ├── autorização e política MFA
   ├── validação e auditoria
   └── acesso a Identity / OpenIddict / persistência
```

O controller deve ser fino: traduz transporte HTTP para o mesmo comando ou
consulta usado pela UI. A UI incorporada pode chamar o contrato diretamente
com a sessão do host. Automação externa chama o controller por HTTP.

Uma UI fora do processo usa HTTP e um cliente tipado. Uma UI no mesmo processo
pode usar HTTP quando houver motivo operacional, mas isso não é requisito de
consistência.

## Autorização

- Controllers e UIs usam o mesmo avaliador de capabilities e recursos.
- Policies de rota podem melhorar challenge, navegação e explicações, mas não
  redefinem a decisão de negócio.
- O use case recebe o operador e o recurso real, aplica tenant/contexto e MFA e
  falha fechado.
- Cookie interativo e bearer são autenticações diferentes na borda, não regras
  de autorização diferentes no domínio.
- A UI não recebe access token ou refresh token apenas para chamar o próprio
  runtime.

## Contratos

- Interfaces, comandos, consultas, resultados e DTOs canônicos são definidos
  uma vez na camada de aplicação.
- A API publica esses contratos em HTTP/OpenAPI sem reimplementar as regras.
- Clientes remotos podem ser gerados a partir do OpenAPI.
- DTOs estritamente visuais podem projetar um resultado, mas não redefinem
  regras de negócio.
- Respostas distinguem `unauthenticated`, `denied`, `step-up-required`,
  `not-found`, conflito, validação e indisponibilidade.

## Violações atuais conhecidas

Os verticais administrativos de clientes, branding e usuários
aplicam o padrão canônico. Controllers HTTP e data sources da UI usam
`IClientManagementService`, `IBrandingManagementService` e
`IUserManagementService` para executar os mesmos casos de uso. Esses serviços
concentram validação, defaults, autorização e auditoria; o escopo DI curto
protege o circuito Blazor sem criar uma segunda implementação. Usuários
incluem acesso, pesquisa paginada, detalhe, criação contextual, atualização de
perfil e reset de senha com validação completa da associação multicontexto.
Atualização de perfil, bloqueio e desbloqueio também passam por esse serviço:
a UI recebe a decisão de capability e apenas envia o comando; Identity,
confirmações, security stamp, tokens, autorizações e auditoria permanecem no
runtime canônico.

Ainda existem violações a migrar:

- páginas da UI pública injetam `UserManager`, `SignInManager` e gerenciadores
  do OpenIddict;
- a Management UI ainda possui conteúdo local sobre ambiente e disponibilidade
  de módulos que precisa vir do contrato canônico;
- o acesso inicial de `Manager` ao shell ainda usa uma role configurada até a
  entrega das capabilities contextuais.

Esses caminhos são débitos de migração, não precedentes arquiteturais. Nenhuma
nova tela deve repetir esse padrão.

## Ordem de migração

1. Expandir o contrato administrativo de sessão com operador, capabilities,
   escopos autorizados, política MFA e metadados necessários ao shell.
2. Migrar configurações e provisionamento para use cases compartilhados
   (branding concluído em 2026-07-29).
3. Criar contratos de aplicação para autoatendimento e migrar a UI pública.
4. Remover das UIs todas as referências a Core, stores e gerenciadores de
   persistência/protocolo.
5. Adicionar testes arquiteturais que falhem quando uma UI ou controller
   reimplementar validação ou acessar dependências proibidas.

## Critérios de aceite

- UI incorporada e controller executam a mesma implementação de cada use case.
- Nenhuma assembly de UI referencia EF Core, Identity stores, OpenIddict
  managers ou SDKs de infraestrutura.
- Controllers não contêm validações ou defaults de negócio ausentes no
  contrato de aplicação.
- Nenhuma capability, regra de tenant ou default de negócio é decidido apenas
  no frontend.
- Testes cobrem o contrato uma vez e verificam a adaptação de UI e HTTP.
- Trocar o adaptador de UI ou HTTP não altera o resultado do domínio.
- Estados de loading, vazio, erro, acesso negado e step-up refletem resultados
  reais do use case.
