# Plano — estratégia de front compartilhado (ai / blazor / identity)

**Status:** proposto — decisão pendente
**Criado:** 2026-08-09
**Escopo:** `sufficit-ai`, `sufficit-blazor`, `sufficit-identity`

## Objetivo

Avaliar a consolidação do front-end dos três projetos numa base de componentes
comum, com suporte a temas por projeto, evitando reescrever componentes já
existentes.

## Recomendação em uma linha

**Não criar um quarto projeto.** O `sufficit-blazor` já é a biblioteca
compartilhada que se pretende construir — o trabalho real é promovê-lo a essa
função e resolver o descompasso de framework, não começar de novo.

## Levantamento

### O que cada projeto usa hoje

| Projeto | Framework | Biblioteca de UI | Papel do front |
| --- | --- | --- | --- |
| `sufficit-blazor` | .NET 9 | MudBlazor (`*`) | RCL + server + client; 338 `.razor` em `src/` |
| `sufficit-ai` | .NET 9 | MudBlazor (`9.*`) | web + client + companion |
| `sufficit-identity` | **.NET 10** | **nenhuma** — CSS próprio | 5 projetos de UI, RCL próprio |

**Nenhum dos três consome os outros hoje.** São três ilhas.

### O `sufficit-blazor` já é uma biblioteca de componentes

`src/Components/` contém, entre outros:

- `MudBlazorExtended/` — `MudButtonEnchanted`, `MudIconButtonEnchanted`,
  `MudNavLinkEnchanted`, `MudNavGroupEnhanted`, `MudSwitchButton`,
  `MudThemeManagerButtonAdmin`. Isto **é** a "nossa versão do MudBlazor".
- `UX/` — `EmptyState`, `SkeletonLoader`, `LoadingButton`.
- `Layout/` — `MainLayout`, `MudThemeContainer`, `FullScreenLayout`,
  `RouteScrollManager`.
- `Shared/` — `ConfirmDialog`, `CopyToClipBoard`, `BreadcrumbNavigation`,
  `LoadingCard`, `ContextSelector`, `APIStatusIconMenuItem`.
- `Tables/` — `GenericTable`, `TableNoRecords`.
- `UI/FilterControl/` — controles de filtro genéricos.

Já existe também infraestrutura de tema: `Services/ThemeService.cs`,
`Components/Layout/MudThemeContainer.razor` e
`wwwroot/assets/js/components/ThemePreference.js`.

O projeto é `Microsoft.NET.Sdk.Razor` com versionamento automático — ou seja,
já está estruturado para ser distribuído como pacote.

### O `sufficit-identity` seguiu outro caminho

Tem seu próprio RCL (`Sufficit.Identity.UI.Components`) com `AppIcon`,
`EmptyState`, `StatusBadge` e `PageHeader`, adotados em 22–25 das 26 páginas de
administração, sobre CSS próprio — sem MudBlazor. Também tem um sistema de
especificação de superfície (`.impeccable/surfaces`) que não existe nos outros
dois.

## O obstáculo real

**Descompasso de framework: .NET 9 (ai, blazor) vs .NET 10 (identity).**

Um RCL Razor precisa ser compatível com quem o consome. Um projeto .NET 9 não
referencia um assembly .NET 10. As saídas possíveis:

1. **Multi-targeting** no RCL compartilhado (`net9.0;net10.0`). Funciona, mas
   dobra a matriz de build e exige que o MudBlazor tenha suporte estável nas
   duas versões.
2. **Subir `ai` e `blazor` para .NET 10.** Mais limpo a longo prazo, mas é uma
   migração com custo próprio e independente deste plano.
3. **Manter o identity fora da base compartilhada** por enquanto, consolidando
   primeiro `ai` + `blazor` (que já estão na mesma versão e já usam MudBlazor).

**Esta decisão é pré-requisito de tudo o mais e não é técnica apenas — é de
roadmap.** Não há como avançar sem ela.

## O segundo obstáculo, menos óbvio

O identity **não usa MudBlazor**. Adotar a base compartilhada nele não é
"referenciar um pacote": é substituir o sistema visual de 26 páginas de
administração mais as telas de conta e vault. Isso é uma reescrita de front,
não uma consolidação.

O identity também tem requisitos que os outros não têm: contratos de estado de
resultado (`ManagementDataResult` com `Forbidden`/`StepUpRequired`/
`Unavailable`), acessibilidade acima da média (119 `aria-label`, `aria-live`,
skip-link) e desenho maduro de ações destrutivas. Qualquer migração precisa
preservar isso, e nada disso vem de graça do MudBlazor.

## Caminho proposto (incremental, cada fase com valor próprio)

### Fase 0 — decisão de framework

Escolher entre multi-targeting, subir tudo para .NET 10, ou consolidar só
`ai` + `blazor` primeiro. **Bloqueia as demais fases.**

### Fase 1 — promover `sufficit-blazor` a biblioteca de fato

Sem criar projeto novo:

- Separar em `Sufficit.Blazor.Components` o que é genérico (MudBlazorExtended,
  UX, Layout, Tables, FilterControl, Dialog) do que é específico de domínio
  (`Shared/Tables/DIDTable`, `UserRolesTable`, `ClientView`, `DIDFreeOption`,
  Features/*). Hoje os dois convivem no mesmo assembly, e é isso que impede o
  reúso — não a falta de um projeto novo.
- Publicar como pacote versionado num feed interno (o repo já tem
  versionamento automático configurado).
- Fixar a versão do MudBlazor. Hoje `sufficit-blazor` usa `Version="*"` e
  `sufficit-ai` usa `9.*`: um float irrestrito num pacote compartilhado
  propaga quebras para todos os consumidores de uma vez.

### Fase 2 — `sufficit-ai` consome o pacote

É o teste real da biblioteca: mesmo framework, mesma lib de UI, e o AI já tem
componentes que provavelmente duplicam os do blazor (`AdminAppBar`,
`AdminBottomNav`, layouts). Cada duplicata eliminada valida a extração.

### Fase 3 — temas por projeto

Com dois consumidores reais, o `ThemeService`/`MudThemeContainer` existente
evolui para um contrato de tema explícito (paleta, tipografia, densidade) que
cada aplicação fornece. Desenhar temas antes de ter dois consumidores é
adivinhação.

### Fase 4 — decidir sobre o `identity`

Só depois das fases anteriores, e como decisão consciente entre:

- **(a)** migrar o front do identity para MudBlazor + base compartilhada
  (reescrita significativa; precisa preservar acessibilidade, contratos de
  estado e as especificações `.impeccable`);
- **(b)** manter o identity com CSS próprio e compartilhar apenas o que é
  agnóstico de biblioteca (tokens de design, contratos de tema, utilitários);
- **(c)** manter separado e aceitar a divergência como custo consciente.

Recomendação preliminar: **(b)**. O identity é um provedor de identidade com
requisitos de acessibilidade e diagnóstico que hoje estão bem resolvidos com
CSS próprio; trocar isso por MudBlazor tem custo alto e ganho incerto.
Compartilhar tokens e contratos captura boa parte do benefício de consistência
visual sem a reescrita.

## O que não fazer

- **Não criar um quarto repositório vazio** e migrar componentes para ele. O
  trabalho difícil (decidir o que é genérico, fixar dependências, versionar,
  temas) é o mesmo; o repositório novo só adiciona um repo a manter e um
  histórico a perder.
- **Não começar pelo tema.** Tema é consequência de ter mais de um consumidor
  real, não pré-requisito.
- **Não fazer big bang nos três ao mesmo tempo.** As fases acima entregam valor
  isoladamente e podem parar em qualquer ponto sem deixar o trabalho pela
  metade.

## Nota de método e limites desta análise

Este documento vem de leitura da estrutura dos três repositórios (csproj,
árvore de componentes, dependências), **não** de uso das interfaces em execução
nem de conversa com quem as opera. Não avaliei qualidade visual, sobreposição
funcional real entre os componentes do `ai` e do `blazor`, nem quanto do
`Shared/` do blazor é genuinamente genérico — isso exige abrir componente a
componente.

A estimativa de esforço da Fase 4 em particular é grosseira: depende de quanto
do CSS do identity codifica comportamento (não só aparência), o que não foi
medido.
