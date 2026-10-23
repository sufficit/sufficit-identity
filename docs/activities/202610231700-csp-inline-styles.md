# CSP sem estilos inline próprios (D1), consentimento NULL (B7) e queda no deploy (23/10/2026)

## D1 — o que a telemetria mostrou

O `report-uri` (`/security/csp-report`) já registrava, com a CSP em
enforce e nonce ligado, estilos **bloqueados** de verdade:

- `style-src-elem` em `/management/*`: o `SUIThemeProvider` da console
  renderizava `<style>` sem nonce — o tema da console não aplicava.
- `style-src-elem` vindo do `blazor.web.js` em duas posições: a UI de
  reconexão padrão do Blazor (injeta `<style>` sem nonce) e o merge do DOM da
  navegação aprimorada, que trazia o `<style>` do tema com o nonce de outra
  resposta.
- Os relatórios de `font-src` (`use.typekit.net`, `data:`) vêm de extensões de
  navegador; nada a fazer.

## D1 — o que mudou (`5cfc13b`)

- Tema público servido em `/branding/theme.css?v=<hash do conteúdo>`
  (`BrandingStylesheet`); cache longo quando a versão confere. O `App.razor`
  público não tem mais `<style>`.
- Console e Vault passam o nonce ao `SUIThemeProvider`.
- `ReconnectModal` (em `UI.Components`) nos três hosts: elemento
  `components-reconnect-modal` com CSS próprio e botão de recarregar em módulo
  JS; o Blazor só alterna classes nele.
- Os 9 atributos `style` da console saíram: barras e medidor de pool usam as
  classes `pct-0..pct-100`; amostras de cor são `<svg><rect fill>`; a prévia do
  Branding define as variáveis por CSSOM (`Branding.razor.js`); o JSON da
  auditoria usa `.audit-json`.
- Larguras de menu do `SUISelect` (`MenuWidth`/`MenuMaxWidth`) viraram
  variáveis CSS no seletor de idioma e na edição de cliente.
- `Csp:StyleAttributes` = `Allow` | `Report` | `Block`. Produção está em
  `Report` desde 23/10: além da política aplicada, um cabeçalho
  `Content-Security-Policy-Report-Only: style-src-attr 'none'` que não
  restringe mais nada, então os relatórios listam só atributos `style`.
- `SUIFormGrid` (sufficit-blazor-ui `2f3016a`): colunas, espaçamento e linhas
  de rótulo em classes; `style` só com `MinColumnWidth` fora do padrão ou
  `Style` do consumidor. **Ainda não publicado**: a publicação do SUI passa
  pelo `build.yml`, que já falhava no orçamento de CSS do Chromium
  (123.696 > 120.832 bytes) antes desta mudança.

Falta para `Block`: SUI publicado com o `SUIFormGrid` novo, e conferir nos
relatórios se o widget do reCAPTCHA (D6) usa atributos `style`.

## D1 — `style-src-attr 'none'` em produção

- Login e login com reCAPTCHA (`verify=1`) abertos num Chromium headless com
  o Report-Only ligado: nenhuma violação no documento (o widget roda em iframe
  do Google, sob a CSP dele). Controle: um `setAttribute('style')` injetado
  gera o relatório, então o detector funciona.
- Zero relatórios de produção desde o deploy.
- SUI `2.26.1023.2034` publicado com o `SUIFormGrid` sem `style`. O orçamento
  de CSS do Chromium subiu para 126 KiB pela regra de +3% já usada
  (124.777 B medidos).
- Identity com o SUI novo e `Csp:StyleAttributes=Block` nos três nós.

## B7

Um cliente sem `consent_type` (`sufficit-endpoints-vault-v3`, só
`client_credentials`) recebeu `explicit`, o que o runtime já aplicava a valor
ausente e o padrão de criação. Distribuição agora: 24 `explicit`, 29
`implicit`, nenhum NULL.

## Queda de ~2 minutos no deploy

O `deploy.py` só levava para a release nova os certificados listados em
`excluded_files`; o `certificate-encryption.pfx` do C2 (mesmo dia) não estava
na lista. Os três nós subiram sem ele, e o serviço entrou em loop de falha na
partida (`FileNotFoundException`). O script mostrou sucesso porque
`systemctl restart` retorna assim que o processo é criado. O HAProxy respondeu
503 até o arquivo ser recolocado nos três nós (cerca de 2 minutos no eveo,
menos nos outros).

Correção (`c7ca454`): todo `certificate*.pfx` é levado, listado ou não, e após
o restart o serviço precisa ficar `active` sem reinício automático por 25 s;
senão a release anterior volta e o rollout para antes do próximo nó. Validado
num deploy real no eveo.
