# Publicação da gestão de audiências

## Objetivo e autorização

Após confirmação do usuário, realizado commit do Identity e deploy sequencial
em eveo, apoint e castrum. Entregues `/management/audiences` e a correção que
impede Configurações de ficar selecionado junto de Proxies confiáveis.
O registro de `chrome.phone` já havia sido aplicado na etapa anterior.

Commit de aplicação: `c79f5bebcbfdcd72d727152119b779ec722ff199`.
Não houve push, migração de banco, mudança na validação de tokens ou publicação
da extensão. Alterações pendentes de Endpoints, extensão e SUI foram preservadas.

## Estado inicial e isolamento do build

Os três nós estavam saudáveis, com `NRestarts=0`, diretórios comuns em
`/opt/sufficit-identity` e binários idênticos. O Server anterior tinha SHA256
`4195e98e7e0d9fdd7873d52fef21333035f114071be2cbcf1502df546a91cc2a`;
SUI anterior: `955d02936a052a7a5d87ab1afb740cb0a95afa2672d718e2ca6293eaede0faca`.

O SUI produtivo informava commit `ee6747d2bb60008b3fbd3d77427ab71bd1a65025`.
O checkout compartilhado continha outras mudanças não commitadas. Para excluí-las,
foram usadas worktrees destacadas do Identity no commit de aplicação e do SUI
nesse commit, com referência local isolada. Fontes SUI não foram modificadas.

Worktrees retidas para reprodução:

- Identity: `.worktrees/audiences-release-20260910`.
- SUI: `../sufficit-blazor-ui/.worktrees/identity-audiences-20260910`.
- Referência vizinha: `.worktrees/sufficit-blazor-ui` aponta ao SUI isolado.

O primeiro restore isolado falhou NU1008 por herança das propriedades centrais
do Identity via symlink. `Directory.Build.props` e `Directory.Packages.props`
vazios (`<Project>`) no SUI isolado delimitaram a herança; não integram o produto.
Locks gerados pelo restore permanecem somente na worktree de build.

## Artefato publicado

- Release, `VersionSuffix=1.26.0910.1834`, `SufficitUseLocalSui=true`.
- Publish: `/tmp/identity-audiences-production.iYtm0T`.
- Pacote: `/tmp/identity-audiences-production.tar.gz`, 11189721 bytes.
- SHA256: `a38a16d6e9957c10f2fa88ed2a84be9eb07d9cace67e729c680c8b312accd356`.
- `REVISION` contém o commit de aplicação; `BUILD-SOURCES.json` registra fontes
  e versão. Configurações, certificados e helpers foram excluídos do pacote.

SHA256 dos assemblies publicados e conferidos em todos os nós:

| Assembly | SHA256 |
| --- | --- |
| Sufficit.Identity.Server.dll | `d671d5e228076e1ee99f814ac2e0d8025bdbdf0382f7e99ca9d9a3d73fb84195` |
| Sufficit.Identity.UI.Management.dll | `d746e76ca1a50d19c98eedcb18ca0cd50318e16ec75f4a7c5acd48268df1f8d8` |
| Sufficit.Blazor.UI.dll | `6701d2733eb381bd78bbb07906af27916ddcbe5906b72adb0aee5d91f6839806` |

## Execução e validação produtiva

Procedimento compatível com diretórios comuns, derivado do último rollout:
lock local de cluster, lease remoto em eveo e lock do serviço em cada nó.
Staging validado nos três nós antes da primeira parada; ativação sequencial,
backup por rename e rollback automático em falha de verificação.
Somente `sufficit-identity` foi reiniciado. Configurações `appsettings*`,
certificados PFX e helpers foram copiados com metadados preservados e conferidos
por hash; ownership do publish alinhado ao serviço `dotnetuser:www-data`.

| Nó | Ativação do serviço (BRT, 10/09/2026) | PID | Resultado |
| --- | --- | --- | --- |
| eveo-apps | 15:38:53 | 2538028 | active / Healthy / NRestarts=0 |
| apoint-apps | 15:38:59 | 566571 | active / Healthy / NRestarts=0 |
| castrum-apps | 15:39:03 | 179008 | active / Healthy / NRestarts=0 |

Rollout terminou com exit 0 e `CLUSTER DEPLOY VERIFIED`. Verificações:

- Readiness e discovery válidos por socket e HTTPS individual com certificado
  verificado (`--resolve identity.sufficit.com.br:443:127.0.0.1` em cada nó).
- Audiências e Proxies confiáveis retornam 302 sem sessão; API de audiências
  rejeita acesso anônimo. Não foi criada sessão administrativa produtiva.
- CSS de audiências/SUI, stylesheet principal e launcher disponíveis; marcadores
  de conteúdo confirmam a interface nova e preservação da proteção do launcher.
- Conjunto JWKS inalterado (2 chaves), fingerprint JSON ordenado SHA256
  `7ea30e14bf9c37f747ceac9257d7469108a5ba74fc8505479ce8d925fe322ad5`.
- Endereço público: `/health/ready` Healthy e `/management/audiences` 302.
- Pós-verificação mantém PIDs e zero reinícios. Journal do serviço desde
  18:38:50 UTC: zero entradas de prioridade 0–3 nos três nós. Isso não substitui
  diagnóstico de eventuais rejeições de autenticação registradas em outros níveis.

## Testes e comandos

Suíte completa: **1194 aprovados, 1 ignorado**, tanto em modo pacote no checkout
principal quanto em modo SUI local isolado. Publish Release aprovado.
Após o relatório, `DocumentationContractTests` passou com 2 testes; também
aprovado `git diff --check`. O registro de deploy recebe commit separado do
commit de aplicação, sem mudar a REVISION publicada.

```sh
dotnet test src/tests/Sufficit.Identity.Tests.csproj -c Release -p:SufficitUseLocalSui=true -p:VersionSuffix=1.26.0910.1834 --logger 'console;verbosity=quiet'
dotnet publish src/server/Sufficit.Identity.Server.csproj --no-restore -c Release -p:SufficitUseLocalSui=true -p:VersionSuffix=1.26.0910.1834 -o /tmp/identity-audiences-production.iYtm0T -v quiet
```

Teste `Audience_browser_host_serves_authenticated_screen` passou novamente na
build isolada com `--no-build --no-restore`, Playwright instalado na extensão e
`IDENTITY_AUDIENCE_BROWSER_SCRIPT` apontando ao script da worktree. Cobriu
adicionar/remover/cancelar, pesquisa, vazio, conflito preservando input, recarga,
foco, falha, menu e ausência de overflow desktop/mobile em servidor de teste.
Não comprova a sessão OAuth do usuário nem um 200 na API Phone de produção.

Logs locais: `/tmp/identity-audiences-deploy-tests.log`,
`/tmp/identity-audiences-isolated-tests.log`,
`/tmp/identity-audiences-production-publish.log`,
`/tmp/identity-audiences-production-browser.log` e
`/tmp/identity-audiences-rollout.log`.

## Recuperação e referências

Backup preservado em cada nó:
`/opt/sufficit-identity.before-audiences-20260910T1834Z`.
Candidato em caso de rollback:
`/opt/sufficit-identity.staging-audiences-20260910T1834Z`.

Scripts locais: `/tmp/identity-audiences-rollout.py` e
`/tmp/identity-audiences-remote.py`; metadados em
`/tmp/identity-audiences-deploy-meta.json`. Remoto e metadados também em `/tmp`
de cada nó. Arquivos temporários não são armazenamento permanente de release.

Rollback requer coordenação exclusiva: adquirir o mesmo lock local de cluster
e manter o lease `/run/lock/sufficit-identity-cluster-deploy.lock` em eveo;
verificar REVISION, backup e ausência do caminho staging; executar o modo
`rollback` do script remoto, um nó por vez, na ordem castrum/apoint/eveo.
Esse modo adquire `/run/lock/sufficit-identity-deploy.lock`, para somente o
serviço, retém o candidato no staging, restaura o backup e valida readiness.
Conferir HTTPS/JWKS após cada restauração. Não reutilizar o rollout de ativação
nem o helper antigo de symlinks. Não houve necessidade de rollback nesta entrega.

- [Implementação e histórico anterior](202609101516-chrome-phone-audience-management.md)
- [Uso e limites de audiências](../management/USAGE-AUDIENCES.md)
- [Tela publicada](https://identity.sufficit.com.br/management/audiences)

A skill software-development orientou isolamento, checkpoints e registro de
rollback; playwright-cli orientou a verificação funcional no navegador.
O plano temporário foi consolidado neste relatório após validação da entrega.
