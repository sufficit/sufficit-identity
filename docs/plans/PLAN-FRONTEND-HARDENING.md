# Plano — endurecimento do front-end (UI pública e Management)

Aberto em 21/10/2026, depois de uma sequência de entregas no mesmo dia:
carimbo de tentativa no login, validação nativa localizada e popup de token.
Uma delas quebrou os cards de `/management/tokens` em produção, com 1.700
testes verdes. Este plano trata das causas, não só do sintoma.

Ordem de execução: 1 → 2 → 3 → 4 → 5 → 6 → 7. Os itens 1 e 2 vêm primeiro
porque barateiam e protegem todos os outros.

| # | Item | Estado |
|---|------|--------|
| 1 | Testes de navegador na CI | feito |
| 2 | CSS por componente nas páginas mais mexidas | feito |
| 3 | Atualização do SUI e correções upstream | pendente |
| 4 | Datas no fuso e no idioma de quem vê | feito |
| 5 | Todo segredo exibido uma vez passa pelo popup | pendente |
| 6 | Mensagens de validação dentro da página | pendente |
| 7 | Ajustes menores (URL do erro, nginx do apoint, baseline visual) | pendente |

## 1. Testes de navegador na CI

**Problema.** O job `build-and-test` exclui `Sufficit.Identity.BrowserTests`.
Os roteiros Playwright em `scripts/*.mjs` só rodam quando alguém define a
variável `IDENTITY_*_BROWSER_SCRIPT` na mão. Nenhuma regressão visual ou de
interação chega à CI.

**Entrega.**
- Job `browser` no `ci.yml`, em `ubuntu-latest` (repositório público):
  instala o Playwright fixado, define as variáveis de todos os roteiros e roda
  só os testes que sobem o host Kestrel com dados fictícios.
- Screenshots dos roteiros publicados como artefato do job, também em caso de
  falha.
- Todo roteiro novo segue o mesmo contrato: uma variável `IDENTITY_*_SCRIPT`,
  a URL do host como argumento e a recusa a qualquer host que não seja
  `127.0.0.1`.

**Pronto quando** o job falha se a quebra de 21/10 for reintroduzida.

## 2. CSS por componente

**Problema.** O `wwwroot/app.css` do Management tem cerca de 7.300 linhas e
só 3 componentes têm `.razor.css`. Uma inserção partiu uma lista de seletores
e quebrou uma tela distante. O CSS de telas removidas fica para trás.

**Entrega.**
- Migrar para CSS isolado (`.razor.css`) as regras de Tokens temporários,
  Provisioning, painel de tokens de registro e popup de token. Filhos SUI são
  alcançados com `::deep`.
- Remover do `app.css` apenas o que migrou. Tokens, variáveis e o layout
  comum continuam globais.
- Teste de sintaxe de folhas (`Stylesheet_selector_lists_are_not_split`) já
  entregue em `ff8c411`. Estender para os `.razor.css`.

**Pronto quando** as páginas migradas não têm regra no `app.css` e o roteiro
de navegador do item 1 continua verde.

## 3. SUI atualizado e correções upstream

**Problema.** O identity trava o `Sufficit.Blazor.UI` em `2.26.920.117`
(20/09). Já existem pontes locais para falhas do SUI: o spinner que não
apagava com o envio bloqueado e o popup confirmando dentro de si mesmo.

**Entrega.**
- No SUI:
  - `SUIDialogHost.CloseRequestAsync` passa a rechecar o diálogo atual depois
    do `await`. Hoje ele apaga um diálogo aberto nessa janela.
  - Textos fixos em português no host (`aria-label="Fechar"`) passam a ser
    parametrizáveis.
  - Gerar release.
- No identity:
  - Subir o lock para a release nova.
  - Remover a ponte do spinner em `identity.js`.
  - Corrigir o que a versão nova exigir.
- Cadência: revisar o lock do SUI a cada release relevante, com o job do
  item 1 como guarda.

**Pronto quando** o lock aponta a release nova, a ponte saiu e a suíte e os
roteiros de navegador passam.

## 4. Datas no fuso e no idioma de quem vê

**Problema.** As telas chamam `ToLocalTime()` 19 vezes com formato
`dd/MM…` fixo. `ToLocalTime()` usa o fuso do servidor. Funciona para nós
(servidor e operadores em São Paulo), mas o identity é produto genérico.

**Entrega.**
- Componente `LocalTime` (UI pública e Management):
  - Renderiza `<time datetime="…">` com fallback em UTC.
  - Formata no navegador (`Intl`) no idioma da página.
- Substituir as ocorrências que exibem instante ao usuário.

**Pronto quando** nenhuma tela formata instante com `ToLocalTime()`.

## 5. Segredos exibidos uma vez

**Problema.** Os tokens já abrem no `OneTimeTokenDialog` (`7434124`). Os
segredos de cliente (criação, rascunho e rotação) e as credenciais de contas
de sistema ainda aparecem inline, sem proteção contra fechar sem copiar.

**Entrega.** Todas essas superfícies passam pelo mesmo popup. Ele ganha um
título por tipo de credencial e continua com a confirmação interna.

**Pronto quando** nenhuma página renderiza um segredo de exibição única fora
do popup.

## 6. Mensagens de validação dentro da página

**Problema.** Os formulários HTTP (login, cadastro, senha) dependem do balão
nativo do navegador. Desde `28abbe6` ele está traduzido, mas some sozinho,
não fica associado ao campo para leitores de tela e não respeita o visual.

**Entrega.** `identity.js` intercepta o `invalid`:
- Mostra a mensagem localizada abaixo do campo (`aria-describedby`,
  `aria-invalid`).
- Foca o primeiro campo inválido.
- Limpa a mensagem quando o campo é editado.
- O balão nativo é suprimido só quando a mensagem própria é exibida.

**Pronto quando** enviar o login vazio mostra a mensagem abaixo do campo,
nos dois idiomas, com o atributo de acessibilidade.

## 7. Ajustes menores

- **URL do erro do login:** depois de exibir o erro e o carimbo, remover
  `error`, `attempt` e `at` da URL com `history.replaceState`. Recarregar não
  repete a mensagem.
- **nginx do apoint-apps:** repassar `Upgrade`/`Connection` no proxy da
  porta 26501, como em eveo e castrum. O Blazor deixa de cair para long
  polling nesse nó.
- **Baseline visual (`.impeccable/review/*.png`):** os arquivos foram
  apagados do disco sem commit e a doc `DESIGN-AUDIENCES.md` aponta para
  eles. Restaurar a partir do Git.

## Registro de execução

Cada item fecha com commit próprio e, quando muda produção, deploy nos três
nós com conferência de versão e health.
