# Texto do botão invisível no hover

Capturas do usuário mostraram o CTA da página AuthorizationError com texto branco no estado normal e invisível no hover. Causa reproduzida em Chromium: `a:hover` de site.css prevalecia sobre a cor da variante SUI preenchida, deixando texto e fundo em rgb(163, 0, 0).

Correção local na regra responsável: `a:where(:not(.sui-btn)):hover` exclui botões SUI e preserva a especificidade anterior para links comuns. Nenhuma alteração na biblioteca, layout, rótulos ou tokens. Referência visual/ledger: capturas do usuário, estado normal do produto e cores da variante SUI existente.

Regressão ButtonHoverTests agora carrega o CSS SUI real antes do CSS do produto. Verifica foreground normal/hover/foco para cinco variantes de anchor buttons em 1280 e 390 px. Antes: 2 casos falharam com branco → vermelho; após: todos os 4 testes passaram, incluindo sublinhado dos links comuns e ausência de movimento no hover.

Comando: `dotnet test src/tests/Sufficit.Identity.BrowserTests/Sufficit.Identity.BrowserTests.csproj --no-restore --filter FullyQualifiedName~ButtonHoverTests --verbosity quiet -- Playwright.LaunchOptions.ExecutablePath=<chrome-headless-shell local>`.

Runner esperava Chromium 1234 não instalado; usado Chromium 1237 já disponível, sem alterar dependências. Navegador real confirmou a página obtida por POST rejeitado sem antiforgery, com stylesheet local interceptado no cliente, em desktop/celular; foreground branco nos três estados. Capturas temporárias em /tmp/identity-hover-patched-1280.png e /tmp/identity-hover-patched-390.png. Sem aprovação de device code real.

## Produção

Publicado pelo fluxo oficial package → prepare → activate-cluster, sequencialmente em app-node-1, app-node-2 e app-node-3. Release `20261014T173425Z-58471de`, revisão `58471de725f2bd7c1b71a63e5a6b4fa318232bad`, archive SHA-256 `bac9527c29e83c6197f8f7f238b31d12bd7f62e1c4e549e134ee86ac40d1524e`. Quatro configurações herdadas por nó; sem alteração de banco/migrations.

Baseline anterior `199e8d2`; gate final: três serviços ativos e uniformes em 58471de, health/ready Healthy. Certificado SHA-256 `5e858b8d138993436730db83743ac67183495e44de8e2e041e72b2882410eefb` e JWKS SHA-256 `85d43862afae2e2eea21c6668aa9ec34fa0c029ac906cd0eaee9122847aed769` preservados. Sem rollback.

Chromium contra produção, sem interceptar stylesheet, confirmou foreground rgb(255, 255, 255) nos estados normal, hover e foco nas larguras 1280 e 390 px; fundo hover rgb(163, 0, 0). Capturas em /tmp/identity-hover-production-1280.png e /tmp/identity-hover-production-390.png. CSS público HTTP 200, Cache-Control no-cache, ETag atualizado. Plano concluído e removido; commits locais sem push.
