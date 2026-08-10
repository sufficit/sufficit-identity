# Plano — consistência de estados no front de administração

**Status:** proposto
**Criado:** 2026-08-09
**Módulo:** `Sufficit.Identity.UI.Management`, `Sufficit.Identity.UI.Components`

## Objetivo

Tornar o tratamento de estados de resultado (sucesso, sem permissão,
step-up necessário, indisponível, não encontrado, inválido) uniforme nas 26
páginas do módulo de administração, extraindo o padrão para o RCL compartilhado
em vez de reimplementá-lo por página.

O princípio já está declarado na especificação de superfície de `Clients.razor`:
*distinguir uma falha de backend de um resultado legitimamente vazio*. Hoje esse
princípio não está propagado — é isso que este plano corrige.

## Diagnóstico

O módulo tem uma base melhor do que uma leitura superficial sugere:

- O RCL `Sufficit.Identity.UI.Components` já existe e é **bem adotado**:
  `AppIcon` em 25/26 páginas, `PageHeader` em 24/26, `EmptyState` em 23/26,
  `StatusBadge` em 22/26.
- `ManagementDataResult<T>` é um contrato rico e bem desenhado: modela
  `Success`, `Forbidden`, `StepUpRequired`, `Unavailable`, `NotFound` e
  `Invalid`, com `ErrorMessage`, `ErrorField` e `ErrorDetails`. Ter
  `StepUpRequired` como estado de primeira classe é maturidade acima da média.
- Acessibilidade acima da média de mercado: 119 `aria-label`, 50 `scope=` em
  cabeçalhos de tabela, 12 regiões `aria-live`, skip-link para `#main-content`.
- Ações destrutivas com desenho maduro: *danger zone* com heading próprio e
  `aria-labelledby`, botão desabilitado durante a operação e feedback
  quantificado do efeito real (quantas credenciais e autorizações foram
  revogadas), em vez de uma confirmação genérica.

O problema não é ausência de infraestrutura compartilhada. É que **o contrato
de resultado é consumido de forma desigual**. Das 24 páginas que consomem
`ManagementDataResult`:

| Outcome | Páginas que tratam |
| --- | --- |
| `StepUpRequired` | 11 |
| `Forbidden` | 8 |
| `NotFound` | 6 |
| `Unavailable` | 3 |
| `Invalid` | 1 |

Consequência prática: na maioria das telas, um operador **sem permissão** e um
**backend fora do ar** produzem a mesma experiência — provavelmente uma lista
vazia. O operador não consegue distinguir "não tenho acesso a isto" de "isto
está quebrado" de "isto está legitimamente vazio". Num painel de administração
de identidade, essa ambiguidade custa tempo de diagnóstico exatamente no
momento em que o tempo é mais caro.

A causa é estrutural, não de disciplina: hoje tratar todos os outcomes exige
escrever a árvore de condicionais à mão em cada página. O caminho de menor
resistência é tratar só o caso feliz. A correção é inverter isso — tornar o
tratamento completo o caminho mais fácil.

## Entregas

- [ ] Criar `ManagementDataView<T>` em `Sufficit.Identity.UI.Components`: recebe
  um `ManagementDataResult<T>` e renderiza o estado correspondente, com
  `RenderFragment` para o caso de sucesso e mensagens padronizadas para os
  demais. Deve compor com `EmptyState` em vez de substituí-lo.
- [ ] Definir mensagens canônicas por outcome (texto, tom e ação de recuperação
  sugerida), para que a mesma condição se apresente igual em todo o módulo.
- [ ] Garantir anúncio acessível das transições de estado (`aria-live`) dentro
  do componente, para que as páginas herdem o comportamento sem repeti-lo.
- [ ] Migrar primeiro as páginas que hoje não tratam `Forbidden` nem
  `Unavailable` — são as que mais ganham.
- [ ] Migrar as páginas restantes, removendo a duplicação de condicionais.
- [ ] Cobrir com testes: cada outcome renderiza o estado esperado; sucesso com
  coleção vazia continua distinguível de falha.
- [ ] Reavaliar as páginas maiores (`Branding.razor` 838 linhas,
  `UserDetail.razor` 675, `Clients.razor` 615) após a migração, para medir
  quanto da extensão era realmente duplicação de estados.

## Fora de escopo

- Redesenho visual, hierarquia de informação ou densidade de tela. Este plano
  trata de consistência de comportamento, não de estética.
- Alterações no contrato `ManagementDataResult<T>`, que está adequado.
- A especificação `.impeccable` por página. Ela deve ser estendida **depois**
  desta entrega: com os estados resolvidos pelo componente, a especificação de
  cada página fica substancialmente mais curta, porque deixa de precisar
  descrevê-los.

## Critério de conclusão

Todas as páginas que consomem `ManagementDataResult` renderizam, através do
componente compartilhado, um estado distinto e acessível para sem-permissão,
step-up, indisponível e vazio-legítimo. Nenhuma página reimplementa essa árvore
de condicionais localmente. Suíte verde e CI (build, testes, CodeQL, gitleaks)
sem regressões.

## Nota de método

O diagnóstico acima veio de leitura de código, não de uso da interface em
execução. Hierarquia visual, densidade de informação, tempos de carregamento e
ergonomia de fluxo real não foram avaliados e podem revelar prioridades
diferentes — convém validar com um operador antes de tratar esta lista como
exaustiva.
