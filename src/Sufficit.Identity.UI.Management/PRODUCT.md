# Product

<!-- impeccable:product-schema 1 -->

## Platform

web

## Stack

Razor Class Library ASP.NET Core Blazor com interatividade no servidor, em
.NET 10. O módulo é incorporado ao composition host `sufficit-identity`, sob
`/management`, e reutiliza sua sessão ASP.NET Identity.

## Users

- Administradores operam clientes OAuth e configurações globais do serviço de
  identidade.
- Gerentes e revendedores administram usuários somente nos contextos sobre os
  quais receberam autoridade.
- Na integração Sufficit, `Administrator` herda todas as capacidades de
  `Manager` com alcance global e acrescenta as capacidades administrativas.
- Ambos usam a mesma aplicação; capacidades e alcance são decididos pela API a
  partir de grants normalizados. O host Sufficit calcula esses grants a partir
  de roles e diretivas contextuais.

Os operadores trabalham em tarefas deliberadas e de maior risco: cadastrar
clientes OAuth, administrar identidades e permissões, publicar branding,
provisionar configurações e investigar alterações.

## Product Purpose

Fornecer a superfície administrativa do Sufficit Identity consumindo os mesmos
use cases que sustentam a Management API. O módulo deve permitir que um operador
autorizado conclua tarefas de identidade com clareza, confirmação e
rastreabilidade, sem ampliar a superfície pública de autenticação nem acoplar a
interface ao armazenamento interno do serviço.

O primeiro sucesso ponta a ponta é cadastrar e administrar um cliente OAuth com
defaults seguros. O produto completo também cobre usuários, papéis, claims,
scopes, sessões, grants, branding, provisionamento e auditoria conforme os
contratos forem publicados pela API.

## Positioning

Esta não é uma coleção genérica de telas de CRUD. A interface conhece as
consequências de cada operação de identidade, torna limites de autoridade
visíveis, protege segredos e preserva o operador humano como sujeito de
auditoria em todo o fluxo.

## Operating Context

- Uso predominantemente em desktop durante configuração, suporte e investigação.
- Acesso mobile e tablet permanece necessário para consulta e intervenções
  pontuais.
- O operador alterna entre listas densas, detalhes técnicos, formulários,
  confirmações e eventos de auditoria.
- Mudanças privilegiadas precisam mostrar intenção, impacto, alvo e resultado.
- Configuração operacional vem de `appsettings`, variáveis de ambiente ou
  secret store; segredos não são editados em páginas de configuração comuns.

## Capabilities and Constraints

- Razor Class Library incorporada ao mesmo host da UI pública.
- Integração por contratos de aplicação compartilhados com a Management API;
  HTTP é opcional quando a UI está incorporada ao mesmo runtime.
- Autenticação pelo cookie `HttpOnly` da sessão ASP.NET Identity do host.
- Nenhum cliente OIDC, access token ou refresh token próprio para a UI
  incorporada.
- Autorização combina escopo administrativo, autoridade do operador e limite do
  recurso.
- Nenhum dado operacional, KPI, cliente, usuário ou evento pode ser inventado.
- Nenhuma página pode consultar banco, gerenciadores de Identity/OpenIddict ou
  serviços de infraestrutura diretamente.
- Capabilities, escopo de tenant, MFA e opções de negócio vêm do mesmo contrato
  de aplicação usado pela API; a UI não mantém uma matriz paralela.
- Estados `loading`, vazio, erro, acesso negado e indisponibilidade precisam
  ser distintos.
- Contrato atual confirmado: clientes possuem listar, obter, criar e excluir;
  branding possui CRUD e ativação; provisionamento possui preview e aplicação
  aditiva.
- Usuários possuem acesso, pesquisa paginada, detalhe, criação contextual,
  atualização de perfil, reset de senha e bloqueio/desbloqueio protegidos por
  escopo completo. A atualização gira o security stamp, revoga tokens ativos,
  preserva autorizações duráveis e reinicia a confirmação dos contatos
  alterados. O bloqueio revoga sessões, tokens e autorizações pelo runtime
  canônico. Exclusão, papéis, claims, scopes isolados, sessões e grants ainda
  dependem de novos contratos; auditoria e branding já usam contratos
  compartilhados.
- O modelo genérico, o adaptador Sufficit e a matriz inicial de capacidades
  estão definidos em
  [`../../docs/management-authorization-architecture.md`](../../docs/management-authorization-architecture.md).
- MFA em operações contextuais é configurável por tenant; a fonte dessa
  política e a exigência global para administração de clientes permanecem
  decisões de implantação.

## Brand Commitments

- Nome do produto: Sufficit Identity.
- Nome deste módulo: Administração.
- Personalidade: profissional, seguro e direto.
- Idioma principal: português do Brasil, usando “você” de modo conciso.
- A identidade visual e os ativos oficiais do produto público permanecem como
  fonte de verdade; a superfície administrativa pode ter composição e densidade
  próprias.

## Evidence on Hand

- Contexto compartilhado do produto: `../../PRODUCT.md`.
- Sistema visual compartilhado: `../../DESIGN.md`.
- Contrato visual administrativo: `DESIGN.md`.
- Investigação arquitetural e inventário atual da API: `README.md`.
- Marca e fonte oficiais: `../Sufficit.Identity.UI/wwwroot/`.
- Não existem métricas administrativas, clientes, usuários ou eventos reais
  disponíveis para material demonstrativo; futuras telas devem continuar
  mostrando estados honestos até a integração.

## Product Principles

1. Separar rotas, shell e policies administrativas da jornada pública de
   autenticação, mesmo quando compartilham o host.
2. Obter toda capability e todo dado operacional pelos mesmos use cases usados
   pela API.
3. Tornar autoridade, consequência e confirmação visíveis antes de mutações.
4. Preservar segredos no servidor e o operador humano na trilha de auditoria.
5. Favorecer tarefas completas e rastreáveis em vez de dashboards decorativos.

## Accessibility & Inclusion

WCAG 2.2 AA é o mínimo. Toda operação deve ser executável por teclado, ter foco
visível, labels e mensagens de recuperação claras. Estado nunca depende apenas
de cor. A interface deve funcionar a partir de 320 px, manter alvos de toque de
pelo menos 44 × 44 px, respeitar `prefers-reduced-motion` e acomodar textos mais
longos em futuras traduções.
