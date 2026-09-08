# Push e deploy — SUI, Identity e Fleet

Pedido explícito: publicar os commits da revisão e fazer deploy.
Skills software-development e sufficit-frontend, já utilizadas na revisão.

## Revisões e destinos

- SUI `1bd4f6d5b5aff97d43d578316971277e1bf675ea`, push main.
  Catálogo: https://sufficit.github.io/sufficit-blazor-ui/?component=SUIStack
- Identity `55268cb0fb5f870627f19f5b051eb24fe3308177`, push main.
  Release `20260908T191117Z-55268cb`, nos nós eveo-apps, apoint-apps e castrum-apps.
  https://identity.sufficit.com.br/management/clients e /vault.
- Fleet `b2f75acc58b6ffd6c52fa6f2e7d97021eebdacb7`, push main após rebase sem
  conflitos sobre `6e867f8`; preserva as mudanças concorrentes de credenciais.
  `/opt/sufficit-fleet`, eveo-ai, https://fleet.sufficit.com.br/console.

## Preparação e execução

O Identity exige SUI local atual no deploy; builds usaram checkout limpo da revisão
SUI acima, sem incorporar o csproj modificado do checkout principal. As worktrees
receberam links temporários para esse checkout. Uma barreira temporária de CPM em
`.worktrees/Directory.Packages.props` impediu que o SUI herdasse as versões centrais
do Identity. Builds dos consumidores foram sequenciais por compartilharem artefatos
SUI. Build Release antes de publish resolveu ausência de assembly de referência
em um primeiro empacotamento. Sem mudança de fonte para esses ajustes de ambiente.
Lockfiles em modo pacote foram preservados; auxiliares temporários removidos.

Identity: `package-release.sh`, `prepare-cluster-release.sh` e
`activate-cluster-release.sh`, com lease coordenado, ativação de um nó por vez e
rollback automático. Cada nó herdou seus quatro arquivos de configuração. Não havia
mudança de schema desde a revisão ativa `5010513`; nenhuma migração foi executada.
Arquivo sem configurações/certificados, SHA-256:
`27181fab15fd366a3a5ebb712cc2e76fb072cecdca1f06c8bce4afef9faba57f`.

Fleet: publish Release da worktree integrada; script `deploy.py` do próprio projeto
com upload de arquivo e troca atômica. Configuração somente em memória apontou para
o publish correto (o caminho padrão apontava para o checkout principal antigo).
`appsettings.json`, `appsettings.Development.json` e data foram preservados; o release
anterior foi mantido em `/opt/sufficit-fleet.prev`. Nenhum serviço Genius ou segredo
foi reconfigurado.

## Verificações

- Identity: 78 testes de UI/rotas/permissões com SUI atual passaram. Ativação confirmou
  três serviços ativos, health/ready Healthy, revisão 55268cb e os mesmos hashes
  de certificado e JWKS em todos os nós. Login público carregou HTTP 200 no Chromium,
  sem erros JavaScript; discovery público também HTTP 200.
- Fleet: 227 testes passaram após rebase e integração com SUI atual. Readiness local
  e público HTTP 200. SHA-256 de Web.dll e SUI.dll idênticos ao publish; configurações
  preservadas por hash. Console sem credenciais retorna 401, inclusive no navegador;
  não se contornou autenticação nem se afirmou teste de sessão autenticada em produção.
- SUI: Build 34267429319 e Pages 34267429240 concluídos com sucesso. Incluem testes de
  componentes, navegadores/acessibilidade nos três engines e Lighthouse. Catálogo
  público mostrou o exemplo novo; Chromium mediu 0px de diferença entre as bases,
  confirmou filtro imediato e alternância pausar/retomar.

## CI e documentação

A CI Identity inicial 34267432693 teve 1060 testes aprovados e uma falha no nome do
novo documento `SUI-ADOPTION.md`. Renomeado para
[EVALUATION-SUI-ADOPTION.md](../frontend/EVALUATION-SUI-ADOPTION.md), com referência
atualizada; os dois contratos de documentação passaram localmente. Essa correção
é documental, sem necessidade de repetir a troca dos binários.

Fleet CI 34267555045: test e controller-image passaram; original-trigger-runner
falhou somente ao enviar o benchmark por cota de artefatos GitHub esgotada. O
benchmark executou, e o erro externo conhecido não afetou o deploy web. Sem retry
sem mudança de condição e sem remover artefatos alheios.

Checkouts principais Identity e SUI avançados por fast-forward. Checkout principal
sujo do Fleet e alteração preexistente do csproj SUI preservados. Plano temporário
encerrado após verificações e registro; nenhuma publicação NuGet foi solicitada.
