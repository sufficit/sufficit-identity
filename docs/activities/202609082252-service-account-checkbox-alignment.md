# Alinhamento de checkboxes nos papéis de contas de sistema

Correção solicitada a partir da captura de `/management/service-accounts`.
A regra local `.sa-role-picker__option` usava `align-items: baseline`,
alinhando o checkbox à linha de base do texto e deslocando seus centros.

## Mudança

Em `src/ui/Sufficit.Identity.UI.Management/wwwroot/app.css`, usar
`align-items: center`; zerar a margem nativa e impedir encolhimento do
checkbox filho. A mesma regra atende edição e criação de contas. Não há
mudança de permissões, callbacks, conteúdo ou biblioteca SUI.

Commit de implementação: `ef6c005f38d00782a28d765af41446a7e71d8633`.

## Evidência

- Fixture Chromium com markup representativo da tela, CSS e fontes reais;
  larguras 900 e 360 px, preferências de cor light/dark. O Management mantém
  seu tema claro. Evidências locais em `/tmp/identity-checkbox-alignment`.
- Antes: diferença vertical entre centros de 2,5 px nas opções da tabela.
  Depois: zero em todos os itens da tabela e criação, inclusive texto com
  quebra de linha em largura estreita.
- Seleção por clique no label e por Space confirmada; captura revisada.
- Restore/build Release do servidor e suas dependências: 13 projetos,
  zero erros e avisos. Correção apenas CSS; sem testes que espelhem a regra.
- `git diff --check` aprovado.

## Publicação

Push na main e rollout pelos helpers oficiais package/prepare/activate.
Worktrees isolados; SUI local `131afdf`, VersionSuffix `1.26.908.2020`
fixado em restore/build/publish e restore em configuração Release.

Release `20260909T015139Z-ef6c005` ativo em eveo-apps, apoint-apps e
castrum-apps. Todos: revisão ef6c005, serviço ativo, health/ready Healthy,
certificados e JWKS iguais aos anteriores. Sem migrations ou rollback.
Os 502 transitórios dos checks durante startup se resolveram dentro da
janela do helper.

Artefato SHA-256:
`c6f91e6d8bdf984a182cbb957a0fbc78324d652190ce05aeef1737ac353d651a`.

CSS publicado HTTP 200 e byte a byte igual ao arquivo validado:
`e9eba59c8c85a47a3f22672b998018fb1bbc0e4266c504465cfda9b1ae1ca6c9`.

A rota protegida redirecionou corretamente ao login (HTTP 200). O fluxo
com dados reais autenticados não foi exercitado; a validação visual usou
fixture sem mutações de contas. Artefatos/logs em
`/tmp/identity-checkbox-deploy`; worktrees temporários removidos.
