---
name: "Sufficit Identity — Administração"
description: "Console operacional seguro, direto e responsivo para administrar o serviço de identidade."
colors:
  brand: "#cc0000"
  brand-hover: "#a30000"
  brand-press: "#7a0000"
  brand-soft: "#fbe9e9"
  brand-ring: "rgba(204, 0, 0, 0.24)"
  ink: "#343132"
  ink-strong: "#1f1d1e"
  ink-muted: "#626064"
  ink-subtle: "#858287"
  surface: "#ffffff"
  surface-page: "#f6f6f7"
  surface-sunken: "#efeeef"
  surface-sidebar: "#242223"
  surface-sidebar-hover: "#343132"
  line: "#e2e1e3"
  line-strong: "#cfced1"
  success: "#157f3f"
  success-soft: "#effaf2"
  warning: "#92540a"
  warning-soft: "#fff8eb"
  danger: "#b42318"
  danger-soft: "#fef3f2"
  info: "#175cd3"
  info-soft: "#eff4ff"
typography:
  display:
    fontFamily: "\"Inter\", -apple-system, BlinkMacSystemFont, \"Segoe UI\", Roboto, Helvetica, Arial, sans-serif"
    fontSize: "clamp(1.75rem, 2.2vw, 2.25rem)"
    fontWeight: 600
    lineHeight: 1.2
    letterSpacing: "-0.018em"
  title:
    fontFamily: "\"Inter\", -apple-system, BlinkMacSystemFont, \"Segoe UI\", Roboto, Helvetica, Arial, sans-serif"
    fontSize: "1.125rem"
    fontWeight: 600
    lineHeight: 1.35
  body:
    fontFamily: "\"Inter\", -apple-system, BlinkMacSystemFont, \"Segoe UI\", Roboto, Helvetica, Arial, sans-serif"
    fontSize: "15px"
    fontWeight: 400
    lineHeight: 1.5
  label:
    fontFamily: "\"Inter\", -apple-system, BlinkMacSystemFont, \"Segoe UI\", Roboto, Helvetica, Arial, sans-serif"
    fontSize: "11px"
    fontWeight: 600
    lineHeight: 1.2
    letterSpacing: "0.08em"
rounded:
  sm: "6px"
  md: "8px"
  lg: "12px"
  pill: "9999px"
spacing:
  xs: "8px"
  sm: "12px"
  md: "16px"
  lg: "20px"
  xl: "24px"
  2xl: "32px"
components:
  button-primary:
    backgroundColor: "{colors.brand}"
    textColor: "{colors.surface}"
    rounded: "{rounded.md}"
    padding: "9px 16px"
    height: "44px"
  button-primary-hover:
    backgroundColor: "{colors.brand-hover}"
    textColor: "{colors.surface}"
    rounded: "{rounded.md}"
  button-primary-active:
    backgroundColor: "{colors.brand-press}"
    textColor: "{colors.surface}"
    rounded: "{rounded.md}"
  button-secondary:
    backgroundColor: "{colors.surface}"
    textColor: "{colors.ink}"
    rounded: "{rounded.md}"
    padding: "9px 16px"
    height: "44px"
  search-field:
    backgroundColor: "{colors.surface}"
    textColor: "{colors.ink}"
    rounded: "{rounded.md}"
    padding: "0 12px"
    height: "44px"
  status-neutral:
    backgroundColor: "{colors.surface-sunken}"
    textColor: "{colors.ink-muted}"
    rounded: "{rounded.pill}"
    padding: "3px 8px"
    height: "24px"
  status-info:
    backgroundColor: "{colors.info-soft}"
    textColor: "{colors.info}"
    rounded: "{rounded.pill}"
    padding: "3px 8px"
    height: "24px"
  panel:
    backgroundColor: "{colors.surface}"
    textColor: "{colors.ink}"
    rounded: "{rounded.lg}"
---

# Design System: Sufficit Identity — Administração

## Overview

**Creative North Star: "Instrumento Operacional de Identidade"**

A Administração amplia a identidade pública da Sufficit com uma composição de
console: profissional, segura e direta. O vermelho identifica marca, ação
primária e pontos de atenção; a maior parte da tela permanece neutra para que
contratos, estados e consequências possam ser lidos sem ruído.

A densidade é moderada e deliberada. Tabelas compactas, navegação persistente e
mensagens diagnósticas tratam o painel como ferramenta de operação, não como uma
coleção decorativa de indicadores. Hierarquia vem de tipografia, contraste,
ritmo e agrupamento; cor nunca substitui texto ou estrutura.

**Key Characteristics:**

- marca vermelha rara sobre superfícies claras e carvão;
- tipografia Inter compacta, com títulos semibold e dados técnicos monoespaçados;
- painéis brancos delimitados por borda fina e elevação quase plana;
- estados explícitos, acionáveis e nunca dependentes somente de cor;
- desktop denso que se transforma em registros rotulados no mobile.

## Colors

A paleta usa um único acento de marca, neutros levemente quentes e cores
semânticas suaves para informar sem competir com a tarefa.

### Primary

- **Vermelho Sufficit** (`colors.brand`): ações primárias, indicadores de rota,
  pequenos ícones de proteção e kickers; estados de hover e pressão usam os
  respectivos tons profundos.
- **Vermelho de Marca Suave** (`colors.brand-soft`): avatares, seleção e fundos
  de baixa ênfase associados à marca.

**The Regra do Vermelho Raro.** O vermelho é reservado à marca, ação primária,
foco e pequenas ênfases; não cobre grandes superfícies nem texto corrido.

### Secondary

- **Azul de Contrato** (`colors.info` e `colors.info-soft`): integração,
  capacidade disponível e informação operacional não destrutiva.

### Tertiary

- **Verde de Confirmação** (`colors.success` e `colors.success-soft`): sucesso
  real e recursos confirmados.
- **Âmbar de Pendência** (`colors.warning` e `colors.warning-soft`): configuração
  incompleta ou atenção recuperável.
- **Vermelho de Perigo** (`colors.danger` e `colors.danger-soft`): falha e
  consequência destrutiva; permanece separado do uso de marca pela função.

### Neutral

- **Tinta Operacional** (`colors.ink`, `colors.ink-strong`): texto corrente,
  títulos e valores importantes.
- **Tinta Silenciosa** (`colors.ink-muted`, `colors.ink-subtle`): descrições,
  metadados e labels secundárias.
- **Papel de Trabalho** (`colors.surface`, `colors.surface-page`,
  `colors.surface-sunken`): painéis, fundo da aplicação e controles em repouso.
- **Carvão de Navegação** (`colors.surface-sidebar`,
  `colors.surface-sidebar-hover`): sidebar persistente e seu feedback de hover.
- **Divisores de Precisão** (`colors.line`, `colors.line-strong`): contornos,
  separadores e campos.

**The Regra do Estado Legível.** Toda cor semântica aparece junto de texto,
ícone ou estrutura que nomeia o estado.

## Typography

**Display Font:** Inter, com a pilha nativa do sistema como fallback
**Body Font:** Inter, com a pilha nativa do sistema como fallback
**Label/Mono Font:** SFMono-Regular, Consolas e Liberation Mono para
identificadores e caminhos

**Character:** A escala é curta e utilitária: títulos firmes, corpo econômico e
labels compactas. A voz visual permanece estável entre conteúdo narrativo e
dados densos.

### Hierarchy

- **Display** (600, responsivo, 1.2): o único `h1` de cada página.
- **Title** (600, 1.125rem, 1.35): títulos de seção e painel.
- **Body** (400, 15px, 1.5): descrições e instruções, normalmente limitadas a
  aproximadamente 68 caracteres por linha.
- **Label** (600–700, 10–11px, tracking positivo): kickers, cabeçalhos de
  tabela e metadados; caixa alta só nas categorias e colunas.
- **Dados técnicos** (11px, monoespaçada): `client_id`, rotas e caminhos de
  configuração, com quebra segura quando necessário.

**The Regra da Escala Curta.** Não introduza títulos gigantes: o painel prioriza
varredura, contexto e comparação, não heroísmo editorial.

## Layout

O shell fixa uma sidebar de 256px e uma topbar sticky de 72px. O conteúdo ocupa
até 1440px, com 32px de gutter e 34px de respiro superior. Seções recorrentes
usam 16–32px de ritmo e painéis reservam áreas estáveis para evitar saltos
durante carregamento.

Abaixo de 1200px a sidebar reduz para 232px e os gutters para 24px. Abaixo de
768px ela vira drawer com scrim, a topbar reduz para 64px e o conteúdo usa 16px
de gutter. Cabeçalhos e ações empilham; tabelas de clientes viram registros
rotulados sem overflow horizontal. Em 420px, controles acessórios da topbar
cedem espaço ao estado principal.

**The Regra da Transformação de Dados.** No mobile, dados tabulares essenciais
mudam de composição; não se limita a reduzir a tabela desktop.

## Elevation & Depth

O sistema é plano por padrão e usa uma combinação de fundo tonal, bordas e duas
sombras. Painéis recebem uma sombra ambiente quase imperceptível; drawer,
skip-link e avisos flutuantes recebem a elevação forte. A topbar pode usar blur
leve apenas como consequência de sua posição sticky.

### Shadow Vocabulary

- **Card ambient** (`0 1px 2px rgba(34, 32, 33, 0.05)`): painéis delimitados
  sobre o fundo da página.
- **Float structural** (`0 14px 34px rgba(34, 32, 33, 0.16)`): elementos que
  realmente se sobrepõem ao plano, como drawer e mensagem global.

**The Regra do Plano por Padrão.** Bordas e contraste tonal estruturam a tela;
sombras fortes só aparecem quando existe sobreposição real.

## Shapes

Controles e navegação usam cantos suavemente curvos de 8px; painéis usam 12px.
Badges e indicadores compactos são pilulares. Ícones de estado e avatares podem
ser circulares, enquanto tabelas preservam geometria retilínea dentro do painel.
Bordas finas e contínuas unem o vocabulário.

**The Regra das Curvas Funcionais.** O raio comunica a categoria do objeto:
controle, painel ou estado compacto; ele não é aplicado como decoração
indiscriminada.

## Components

Os componentes são contidos, densos e explícitos. Estados de hover, foco,
pressão e indisponibilidade preservam a mesma geometria.

### Buttons

- **Shape:** controle de 44px com cantos suavemente curvos.
- **Primary:** vermelho de marca, texto branco, peso 600 e padding compacto.
- **Hover / Focus:** vermelho aprofunda no hover e pressão; foco usa anel de
  3px com offset de 2px.
- **Secondary:** superfície branca, contorno forte e fundo rebaixado no hover.
- **Disabled:** mantém o rótulo e explica a indisponibilidade; reduz opacidade e
  bloqueia interação.

### Chips

- **Style:** badges de estado têm altura mínima de 24px, forma pilular, texto
  semibold e combinação tonal de fundo, borda e texto.
- **State:** neutral, success, warning, danger e info sempre carregam um rótulo;
  ícones são opcionais, nunca o único identificador.

### Cards / Containers

- **Corner Style:** painéis com cantos de 12px.
- **Background:** branco sobre o fundo cinza da página.
- **Shadow Strategy:** sombra ambiente baixa, acompanhada de borda fina.
- **Border:** divisor neutro; variantes informativas usam contorno semântico
  suave.
- **Internal Padding:** 16–24px conforme densidade; tabelas integram toolbar,
  dados e rodapé no mesmo contêiner.

### Inputs / Fields

- **Style:** altura mínima de 44px, fundo branco, borda forte, cantos de 8px e
  label sempre disponível, visualmente ou para tecnologia assistiva.
- **Focus:** borda vermelha e anel de 3px.
- **Error / Disabled:** fundo rebaixado e estado textual; mensagens explicam
  recuperação junto ao contexto.

### Navigation

A sidebar carvão agrupa rotas por seção. Itens têm alvo mínimo de 44px, ícone e
texto; hover clareia a superfície e a rota ativa combina fundo vermelho
translúcido, texto branco e indicador lateral. No mobile, a navegação vira
drawer, fecha por Escape e devolve o foco ao botão de abertura.

### Tabela operacional

O cabeçalho usa labels compactas em caixa alta; células usam 13px por 16px de
padding e divisores finos. Nome recebe peso 600, identificador usa mono, estados
usam badge ou ponto acompanhado de texto. Loading reserva 290px com skeleton;
vazio e falhas ocupam o mesmo instrumento com mensagem e uma ação de
recuperação.

### Empty state

Ícone circular neutro, título curto, descrição de baixa ênfase e no máximo uma
ação de recuperação. Estados vazio, não configurado, `401`, `403`, indisponível
e resposta inválida precisam ser textualmente distintos.

## Do's and Don'ts

### Do:

- **Do** mantenha um único `h1`, descrição curta e no máximo uma ação primária
  no cabeçalho.
- **Do** reserve alvos de interação de pelo menos 44 × 44px e foco visível de
  3px.
- **Do** mostre loading, vazio, erro, autenticação, autorização e
  indisponibilidade como estados distintos e recuperáveis.
- **Do** transforme tabelas essenciais em registros rotulados abaixo de 768px.
- **Do** use dados reais do contrato e mantenha segredos fora da interface.
- **Do** respeite `prefers-reduced-motion` removendo animações não essenciais.

### Don't:

- **Don't** invente KPIs, clientes, usuários ou estados para preencher a tela.
- **Don't** use vermelho em grandes áreas, texto corrido ou como substituto de
  hierarquia.
- **Don't** esconda indisponibilidade, autoridade ou consequência atrás de
  ações apenas por ícone.
- **Don't** introduza glassmorphism, gradientes decorativos, sombras profundas
  ou dark mode parcial.
- **Don't** force tabelas essenciais a ultrapassar o viewport mobile.
- **Don't** exponha tokens, segredos, exceções ou identificadores completos em
  logs e mensagens transitórias.
