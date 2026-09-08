# Adoção da Sufficit.Blazor.UI no Identity

Revisão de 2026-09-08, sobre `f2fb33a`. A UI consome o pacote **1.28.0** quando
`SufficitUseLocalSui=false`; um checkout irmão pode fornecer código mais recente.
Não confundir compilar com a biblioteca local com validar o pacote publicado.

## Inventário

Contagens estáticas de tags nos arquivos Razor (ocorrências de código, não instâncias
renderizadas; incluem branches e fallbacks). “Campos nativos” agrupa `input`,
`select`, `InputText`, `InputSelect` e `InputCheckbox`.

| Módulo | SUI antes → depois | Botões nativos antes → depois | Campos nativos antes → depois |
| --- | ---: | ---: | ---: |
| UI pública/account/manage/device | 2 → 2 | 38 → 38 | 41 → 41 |
| Management | 529 → 535 | 110 → 106 | 93 → 91 |
| Vault | 42 → 71 | 17 → 0 | 5 → 0 |
| UI.Components / UI.Abstractions | 0 → 0 | 0 → 0 | 0 → 0 |

Management já usa extensivamente SUI, mas **o projeto inteiro ainda não atingiu a
adoção máxima útil**. Esta revisão migrou os controles de aplicações e o Vault;
não é uma migração integral dos demais formulários.

## Aplicado

- Aplicações: busca e scope usam `SUITextField`; os quatro `SUISelect` recebem
  `Label`, associando rótulo ao controle; limpar/repetir/paginar usam `SUIButton`.
- A grade `clients-filters` deixou de acumular `data-toolbar__actions`. Essa classe
  genérica vinha depois no CSS e sobrescrevia `display:grid` por `display:flex`,
  além do alinhamento. A grade específica conserva suas colunas responsivas.
- Vault: cinco campos, dezessete botões e cinco links de ação passam a usar SUI;
  `SUIFormGrid` organiza os dois formulários de segredos. Navegação semântica,
  links de linhas e autorizações continuam no módulo de domínio.
- O Vault fornece tokens de marca e altura de controle em seu layout, valendo no
  host independente e no host incorporado. Removidas regras duplicadas de campos
  e variantes de botão.

## Compatibilidade que precisa ser preservada

O pacote 1.28.0 não implementa `AdornmentIcon` de `SUITextField`, embora atributos
não reconhecidos sejam aceitos e encaminhados ao HTML. As buscas preservam a lupa
com `SUIIcon` decorativo junto do campo. A propriedade da versão local mais recente
não deve ser usada como se já estivesse no pacote consumido.

Nos formulários do Vault, `ValueChanged` atualiza o modelo e notifica o
`EditContext`; `ValidationMessage` permanece explícito. Isso conserva a validação
por DataAnnotations e a limpeza dos erros ao editar com 1.28.0. Uma atualização
futura deve validar a integração nativa de `SUIFieldBinding` antes de remover essa
compatibilidade, para não duplicar mensagens. Senhas continuam `type=password`,
com `autocomplete=new-password` e os limites originais. Não alteramos os serviços,
políticas ou operações de armazenamento.

## Oportunidades restantes por módulo

- **Management / ClientEdit e ClientDraft:** escolhas compostas de grants/scopes,
  listas de URIs, checkboxes e ações específicas. Migrar por fluxo, preservando
  a revisão do rascunho e a semântica de seleção; não substituir cartões inteiros
  por um checkbox apenas porque ambos representam uma escolha.
- **Management / Branding:** inputs de cor/arquivo, previews e ações de upload
  exigem verificar o equivalente SUI e seu contrato de arquivo antes da troca.
- **Management / Claims, Sessions, Authorizations, UserCreate/UserEdit e detalhes:**
  ainda há buscas, ações e campos nativos candidatos. Preservar paginação, filtros
  de URL, formulários e políticas; conferir cada callback e o pacote consumido.
- **UI pública:** login de senha exige POST HTTP completo para emitir o cookie;
  consentimento, logout e fluxos de conta carregam antiforgery e campos nomeados.
  Hidden inputs, fallback de cultura sem JS e formulários HTTP são intencionais.
  Já os controles interativos de gestão de conta ainda são candidatos: precisam
  de uma rodada própria de testes de login, MFA/passkeys e retorno ao cliente.
- **UI.Components:** não criar wrappers locais de componentes SUI só para mudar
  nomes. O projeto hoje serve como referência/estrutura compartilhada, sem Razor
  visual duplicado.

## Padrão de alinhamento reutilizável

Para uma barra de campos com rótulo e botões sem rótulo, usar `SUIStack Row Wrap
AlignItems="End"`. É a mesma intenção já aplicada pela grade de Metrics. Para
campos com ajuda/erro, usar `SUIFormGrid` alinhando o início dos campos e deixar as
ações após a grade; alinhar pela base de wrappers com alturas de ajuda diferentes
não alinha os inputs. Não alterar o alinhamento global de todos os campos.

## Evidência

- Builds Management/Vault e 78 testes de UI, rotas, composição e autorização com
  `-p:SufficitUseLocalSui=false`.
- Clientes: HTML SSR real do test host (serviços de teste) e CSS real de 1.28.0;
  seis controles na mesma linha, 44px de altura; sem overflow em 390px.
  Essa inspeção estática não equivale a testar a navegação autenticada de produção.
- Vault: componente real em host local isolado, sem serviços de persistência;
  campos alinhados em 1280px e empilhados em 390px; obrigatórios, caminho inválido
  e desaparecimento de erro após correção exercitados no navegador.
- Não houve publicação, mudança de versão de pacote ou alteração de lockfiles.
