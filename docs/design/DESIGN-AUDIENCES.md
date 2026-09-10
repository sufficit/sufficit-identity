---
name: "Sufficit Identity — Audiências"
description: "Regras observadas do inventário e dos vínculos manuais de audiências."
---

# Design System: Sufficit Identity — Audiências

## Overview

A superfície `/management/audiences` opera no modo Operate e estende a console
existente. A autoridade global permanece em
[DESIGN-MANAGEMENT-UI.md](DESIGN-MANAGEMENT-UI.md); este registro descreve apenas
Audiences, conforme os compromissos de [PRODUCT.md](../../PRODUCT.md).

Evidência: [Audiences.razor](../../src/ui/Sufficit.Identity.UI.Management/Components/Pages/Audiences.razor),
[CSS local](../../src/ui/Sufficit.Identity.UI.Management/Components/Pages/Audiences.razor.css),
[Scopes](../../src/ui/Sufficit.Identity.UI.Management/Components/Pages/Scopes.razor),
[NavMenu](../../src/ui/Sufficit.Identity.UI.Management/Components/Layout/NavMenu.razor)
e [app.css](../../src/ui/Sufficit.Identity.UI.Management/wwwroot/app.css).
Capturas fornecidas: [desktop](../../.impeccable/review/desktop.png),
[mobile](../../.impeccable/review/mobile.png),
[falha desktop](../../.impeccable/review/desktop-failure.png) e
[falha mobile](../../.impeccable/review/mobile-failure.png).

## Colors

Herda vermelho Sufficit para ação primária e neutros para shell, painéis e dados.
Informação, sucesso e falha usam os tratamentos semânticos existentes com texto
e ícone. A superfície não define uma paleta própria.

## Typography

Mantém a hierarquia compacta da console: título de página, títulos de seção,
instruções e rótulos de tabela. Audiências e identificadores de clientes usam
`code`; nomes de scopes são links. Não introduz uma escala tipográfica local.

## Layout

Cabeçalho com ação primária, faixa explicativa, formulário ou confirmação inline
quando abertos e painel de inventário com pesquisa, tabela e rodapé. O formulário
reutiliza duas colunas no desktop e empilha campos e ações no mobile.

A tabela reutiliza a variante de Scopes: Audiência, Scopes vinculados e Clientes
autorizados. Até 767px, o cabeçalho tabular desaparece e cada registro apresenta
células rotuladas por `data-label`, com grade de rótulo/valor
`minmax(96px, 0.38fr) minmax(0, 0.62fr)`. O rodapé empilha seus itens.

A última coluna contém dados, portanto o CSS local substitui a largura global de
ações (52px) por `auto`; no mobile, a última célula e a pesquisa usam `100%`.
Identificadores e links longos quebram com `overflow-wrap: anywhere`; listas de
vínculos permitem quebra entre link, badge e ação.

## Components

- Reutiliza `SUIPageHeader`, `SUIIcon`, `SUIFormGrid`, `SUITextField`, `SUISelect`,
  `SUIStatusBadge` e `SUIEmptyState`, além dos botões, avisos e painéis existentes.
- Vínculos de manifesto exibem badge textual e não oferecem remoção. Vínculos
  manuais apresentam ação com nome acessível contendo audiência e scope, conforme
  a permissão. Clientes ficam em `details`/`summary` com contagem; ausência tem texto.
- O formulário explica sensibilidade a maiúsculas e efeito sobre novos tokens.
  Remoção exige confirmação inline que identifica o vínculo e suas consequências.
  Salvamento e remoção exibem andamento e bloqueiam ações concorrentes.
- Carregamento usa skeleton e `aria-busy`. Vazio, pesquisa sem correspondência e
  falha têm mensagens distintas; falha oferece “Tentar novamente”. O rodapé com
  `role="status"` mostra “Carregando…”, contagem somente após sucesso, ou
  “Nenhum resultado carregado” em falha. Sucesso da gravação pode coexistir com
  falha da consulta seguinte: os avisos descrevem operações diferentes.
- Falha de alteração usa `role="alert"`; conflito oferece “Atualizar para revisar”.
  Abrir formulário ou confirmação foca seu título após renderização. Cancelar ou
  concluir com sucesso foca “Audiências registradas”. Atualizar para revisão foca
  o formulário se ainda aberto, senão o inventário. Os títulos usam `tabindex="-1"`;
  o foco visível herda o contorno global de 3px e afastamento de 2px.
- A navegação mantém a seleção existente de Audiences. “Configurações” usa
  correspondência exata (`NavLinkMatch.All`), evitando seleção por prefixo ao
  acessar TrustedProxies.

## Do's and Don'ts

- **Do** preserve a tabela responsiva, os componentes compartilhados e o retorno de foco.
- **Do** diferencie falha de consulta, inventário vazio e sucesso da alteração.
- **Don't** replique tokens globais nem promova ajustes de largura locais a regras da console.
- **Don't** trate dados das capturas como conteúdo de produção ou invente novas variantes visuais.
