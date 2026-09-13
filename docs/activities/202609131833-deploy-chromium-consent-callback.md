# Deploy do callback Chromium após consentimento OAuth

## Objetivo e estado inicial

Publicar a correção CSP que permite concluir o consentimento OAuth da extensão
Chrome no callback registrado, sem levar para produção as alterações posteriores
e ainda não publicadas da `main`.

Os três nós estavam ativos, prontos e uniformes na revisão
`03243f37748f1332eacccf5405147d3db3cc0155`, com SHA-256 do STS
`860d608308aaaea7408d8460b57e22ead9b3eff3d11cd5e3b6b1a8a8b4d7591e`.
Certificado e JWKS também estavam uniformes.

## Artefato isolado

A revisão de produção foi reconstruída em worktree isolada com o SUI
`3d84927b5730dc8f669412c97491a7b4e81675b7`, registrado no deploy anterior.
Somente `SecurityHeadersMiddlewareExtensions.cs` e os testes CSP receberam o
delta revisado que também existe na `main` a partir de `c346be6`.

O hotfix foi versionado como:

- commit: `d35f6bc7c71c080c9c7413750e878924a24cea4c`;
- tag remota: `production/20260913T212609Z-chromium-consent-callback`;
- release: `20260913T212609Z-d35f6bc-csp-consent`;
- 365 arquivos no pacote;
- pacote SHA-256: `38b363658d9df45933bc2421d18959896d51406a76a6934b969bff7e6b37784c`;
- `Sufficit.Identity.STS.dll` SHA-256:
  `c86edf6164a7d5bb9df06437c9818fd4f7e4df97c58ada0ff17a410637e33749`.

O pacote não contém `appsettings*.json` nem `certificate*.pfx`. Não houve
migration, alteração de schema ou mudança de configuração.

## Validação antes do rollout

```bash
dotnet test src/tests/Sufficit.Identity.Tests.csproj \
  --filter FullyQualifiedName~CspHeaderTests -c Release --no-restore
dotnet build src/server/Sufficit.Identity.Server.csproj \
  -c Release --no-restore -warnaserror
dotnet test src/tests/Sufficit.Identity.Tests.csproj \
  -c Release --no-build --no-restore
dotnet format Sufficit.Identity.sln --verify-no-changes --no-restore \
  --include src/sts/SecurityHeadersMiddlewareExtensions.cs \
  src/tests/CspHeaderTests.cs
git diff --check
```

Resultados: 20 testes CSP e 1.215 testes totais aprovados, build com zero
warnings/erros, formatação e diff aprovados. Um restore inicial com
`--locked-mode` foi corretamente recusado porque o build de produção usa o SUI
local; o restore documentado sem esse modo passou e nenhum lock file entrou no
commit.

## Preparação e ativação

O wrapper novo de preparação recusou o layout físico legado de
`/opt/sufficit-identity` antes de criar candidato ou parar serviço. Foi então
usado o procedimento compatível já validado no deploy anterior: lease global
em Eveo, lock por nó, staging físico, herança e comparação de conteúdo/UID/GID/
modo de configurações, certificados e helpers, ativação sequencial e rollback
automático.

Antes da ativação, os três candidatos continham o STS esperado e os serviços
continuavam saudáveis na revisão anterior. A CSP ainda não admitia o callback,
confirmando a reprodução; uma URL não registrada permanecia negada.

| Nó | Ativação (Brasília) | PID | Restarts |
|---|---:|---:|---:|
| eveo-apps | 18:32:02 | 2020874 | 0 |
| apoint-apps | 18:32:08 | 2140320 | 0 |
| castrum-apps | 18:32:13 | 2528268 | 0 |

## Resultado em produção

Todos os nós executam `d35f6bc7c71c080c9c7413750e878924a24cea4c`,
com o mesmo STS do pacote, serviço ativo, health/readiness saudáveis e zero
restarts. Permaneceram inalterados e uniformes:

- certificado SHA-256:
  `5e858b8d138993436730db83743ac67183495e44de8e2e041e72b2882410eefb`;
- JWKS SHA-256:
  `85d43862afae2e2eea21c6668aa9ec34fa0c029ac906cd0eaee9122847aed769`;
- issuer: `https://identity.sufficit.com.br/`;
- manifests persistentes específicos de cada nó.

Verificações diretas em cada nó e pelo endpoint público confirmaram:

- callback registrado
  `https://khnhmfhcccepdklfflcjlbkanhogmffl.chromiumapp.org/` presente em
  `form-action` na resposta de consentimento;
- callback `https://unregistered.invalid/callback` ausente da política;
- discovery, health e readiness públicos válidos;
- journals de prioridade `err` vazios após a ativação.

O fluxo OAuth completo depende da interação e da sessão real do usuário e não
foi executado em seu nome. O contrato de servidor que causava
`Authorization page could not be loaded` está corrigido e publicado; a extensão
deve iniciar um novo login para abandonar a tentativa bloqueada anterior.

## Rollback

O backup anterior foi preservado em todos os nós:

`/opt/sufficit-identity.before-csp-20260913T212609Z-d35f6bc-csp-consent`

Uma reversão deve adquirir o mesmo lease global, restaurar os nós na ordem
Castrum → Apoint → Eveo e validar a revisão `03243f3`, readiness, certificado e
JWKS após cada troca.
