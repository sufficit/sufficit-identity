# Texto do botão invisível no hover

Capturas do usuário mostraram o CTA da página AuthorizationError com texto branco no estado normal e invisível no hover. Causa reproduzida em Chromium: `a:hover` de site.css prevalecia sobre a cor da variante SUI preenchida, deixando texto e fundo em rgb(163, 0, 0).

Correção local na regra responsável: `a:where(:not(.sui-btn)):hover` exclui botões SUI e preserva a especificidade anterior para links comuns. Nenhuma alteração na biblioteca, layout, rótulos ou tokens. Referência visual/ledger: capturas do usuário, estado normal do produto e cores da variante SUI existente.

Regressão ButtonHoverTests agora carrega o CSS SUI real antes do CSS do produto. Verifica foreground normal/hover/foco para cinco variantes de anchor buttons em 1280 e 390 px. Antes: 2 casos falharam com branco → vermelho; após: todos os 4 testes passaram, incluindo sublinhado dos links comuns e ausência de movimento no hover.

Comando: `dotnet test src/tests/Sufficit.Identity.BrowserTests/Sufficit.Identity.BrowserTests.csproj --no-restore --filter FullyQualifiedName~ButtonHoverTests --verbosity quiet -- Playwright.LaunchOptions.ExecutablePath=/home/hugodeco/.cache/ms-playwright/chromium_headless_shell-1237/chrome-headless-shell-linux64/chrome-headless-shell`.

Runner esperava Chromium 1234 não instalado; usado Chromium 1237 já disponível, sem alterar dependências. Navegador real confirmou a página obtida por POST rejeitado sem antiforgery, com stylesheet local interceptado no cliente, em desktop/celular; foreground branco nos três estados. Capturas temporárias em /tmp/identity-hover-patched-1280.png e /tmp/identity-hover-patched-390.png. Sem aprovação de device code real.
