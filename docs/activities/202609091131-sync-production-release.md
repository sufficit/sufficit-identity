# Integração e publicação do Identity

Pedido: sincronizar mudanças pendentes, mesclar PRs e publicar a versão integrada.

PR #63 integrou #50/#51 (CodeQL), #53 (NUnit adapter 6.3), #58
(OpenIddict 7.7 e locks completos), além do arquivamento self-service de tokens
inativos previamente presente no checkout local. A cópia original foi preservada
em cache e conferida por SHA-256. Nenhuma migração de esquema foi necessária.

## Validação

- Build Release com `-warnaserror` e 1079 testes aprovados em modo pacote.
- Build Release com `-warnaserror` e 1079 testes aprovados com SUI local
  `4bd05529cdfcc55c2f0c5b5e9727b7c911905f8b`, versão `1.26.908.2020`.
- Locks comprometidos permanecem em modo pacote para CI. O worktree SUI local
  teve uma fronteira temporária de Directory.Build.props para impedir a herança
  do gerenciamento central de pacotes do diretório Identity pai.

## Publicação verificada

Revisão implantada: `738759ad06606d4c0755d0a917293739017bd47a`.
Pacote: `20260909T142529Z-738759a`.
SHA-256: `738652aac95ecee5e0262a08dc231dafb503698e4e469642294b4961995284c0`.
Baseline/rollback: `dc52b2567b1b22b67c120f9699d9f5bb9ba68ffa`.

Executados `helpers/package-release.sh`, `prepare-cluster-release.sh` e
`activate-cluster-release.sh`. A ativação foi sequencial em eveo-apps,
apoint-apps e castrum-apps; todos passaram no gate final com revisão uniforme,
serviço ativo, health e readiness saudáveis. Quatro configurações por nó foram
herdadas do release anterior; certificado e JWKS permaneceram iguais à baseline.
Os 502 transitórios durante a inicialização cessaram antes do gate de cada nó.

As rotas públicas `/health`, `/health/ready`, `/.well-known/openid-configuration`
e `/api/integrations/oauth/completion.js` responderam HTTP 200. O script servido
contém a conclusão de integração e fechamento da janela. A correção de retorno
Google de #60 está agora em produção; não foi realizado novo consentimento
interativo com uma conta Google real nesta publicação.

Referências: https://github.com/sufficit/sufficit-identity/pull/63 e issue #62.
Logs, manifesto do pacote e verificações preservados no cache privado operacional
`sufficit-ai-genius/sync-release`. Nenhum segredo foi incluído no repositório.
