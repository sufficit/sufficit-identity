# /manage: espaçamento do título Outros recursos

A captura do usuário mostrou os links encostados no título. A margem de
20px já existia, mas `.auth-card h2` tinha maior especificidade que
`.manage-resources__heading` e a zerava.

Em `src/ui/Sufficit.Identity.UI/wwwroot/css/site.css`, o seletor da margem
passou a `.manage-resources > .manage-resources__heading`. As declarações
visuais restantes ficaram no seletor original para preservar tamanho/cor
do título. Nenhuma mudança de conteúdo, permissões, navegação ou SUI.

Commit publicado: `dc52b2567b1b22b67c120f9699d9f5bb9ba68ffa`.

## Validação

Fixture Chromium com CSS e fontes reais, em 1200px e 360px, com um e dois
links: distância do título ao primeiro link passou de zero para 20px.
Fonte de 18px, cor, margem do título do perfil e 8px entre links mantidos;
sem overflow horizontal. Captura revisada. Evidências locais:
`/tmp/identity-manage-spacing` (script, medidas e capturas antes/depois).

Release build: 17 projetos, zero erros/avisos. Os três testes existentes de
VaultUiCompositionTests passaram. `git diff --check` aprovado. O teste de
texto CSS existente não detectava a cascata defeituosa; o espaçamento real
foi confirmado em navegador.

## Deploy

Fontes isoladas e SUI local 131afdf, VersionSuffix=1.26.908.2020 fixado em
restore/build/publish, restore Release. Helpers oficiais de package,
prepare e activate; configurações preservadas e ativação sequencial.

Release `20260909T015547Z-dc52b25` ativo em eveo-apps, apoint-apps e
castrum-apps. Revisão uniforme dc52b25, serviços ativos, health/ready
Healthy, certificados e JWKS preservados. Checks tiveram respostas 502
transitórias durante startup, recuperadas na janela prevista. Sem rollback
ou migrations.

SHA-256 do artefato:
`abbd675d3ea76f564407cd5ebb5da818dfa2b7934df6ea059d3f1aec0784a9bc`.

CSS público HTTP 200, byte a byte igual ao validado; SHA-256:
`f8ba3f47629c68e034a3a8f85819f79bab42ff686574ac90a28d975d6a5c4bd3`.

Rota /manage redireciona ao login para acesso anônimo (HTTP 200 final).
Não foi exercitado fluxo autenticado com dados reais: validação visual em
fixture, publicação confirmada pelo asset e pelos checks operacionais.
Worktrees temporários removidos; logs/artefato em
`/tmp/identity-manage-deploy`.
