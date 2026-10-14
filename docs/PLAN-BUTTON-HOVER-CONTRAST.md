# Contraste do botão de recuperação

Objetivo: corrigir texto invisível ao passar o mouse no botão da página amigável, preservando o visual e o contrato SUI.

1. CONCLUÍDO — Reproduzir a regra de cor vencedora no navegador e adicionar regressão de contraste.
2. CONCLUÍDO — Corrigir a regra responsável e validar hover/foco/estado normal com CSS real.
3. EM ANDAMENTO — Publicar correção nos três nós pelo rolling deploy já autorizado, conferir HTTP e navegador público.
4. PENDENTE — Registrar evidências e finalizar entrega.

Referência/ledger: capturas do usuário e estado normal existente determinam texto branco e fundo vermelho; SUI define variantes e tokens. A regra local de links comuns não deve alterar a cor de botões SUI.
Validação: BrowserTests ButtonHoverTests, navegador Chromium com página e CSS reais, package/prepare/activate-cluster e health/ready/cert/JWKS.

Regressão Chromium com SUI real + site.css: 2 testes falharam (1280/390 px), texto branco tornou-se rgb(163, 0, 0); 2 testes antigos passaram. Usado Chromium instalado via parâmetro LaunchOptions.ExecutablePath porque a versão esperada pelo runner não estava instalada.

Validação antes do deploy: 4 BrowserTests passaram com CSS real; navegação Chromium real ao POST de erro, CSS local interceptado no navegador, 1280/390 px: texto branco em normal/hover/foco sobre hover rgb(163, 0, 0). Capturas /tmp/identity-hover-patched-{1280,390}.png conferidas.
