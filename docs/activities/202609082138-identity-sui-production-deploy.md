# Identity: deploy da SUI atualizada

## Objetivo e estado inicial

Publicar a atualização de SUI já aprovada na main do Identity. Os três nós
(eveo-apps, apoint-apps e castrum-apps) estavam saudáveis na revisão
`823c74e0add6d250de628afa8a1d83dcabd62ae4` antes do rollout.

## Entrega

- Identity: `a9f2f25374ff67fffa6b98072703f54fafdb1c16`.
- SUI local: `131afdf421885d45df8f71761723d21d9b9dd168`, com o mesmo código
  de componentes da versão publicada `1.26.908.2020` (mudanças posteriores
  ao commit `25b06e8` são de CI, manutenção e documentação).
- Release ativo nos três nós:
  `/opt/sufficit-identity.releases/20260909T003713Z-a9f2f25`.
- Artefato SHA-256:
  `bb666939d3fa45fdf3c785bf998583e6eaf8246b0050971a2c2f7419c104a6ab`.
- DLL SUI SHA-256, conferido no artefato e nos três nós:
  `aff59dd61f955cab4f15b2b4e5fd1c6f80b7b3413cba536f3931dd48f3bf70ce`.

O publish usou o projeto SUI irmão em worktrees isolados, conforme DEPLOY.md;
não consumiu o binário NuGet. `VersionSuffix=1.26.908.2020` foi fixado em
restore/build/publish, e o restore recebeu `-p:Configuration=Release`.
A DLL e o deps.json resultantes identificam SUI `1.26.908.2020`; a versão
informacional contém o commit SUI `131afdf`.

A primeira inspeção detectou deps.json com a versão Debug produzida pelo
restore padrão, apesar de a DLL ser Release. O candidato
`20260909T003558Z-a9f2f25` foi preparado, mas nunca ativado. O artefato foi
regenerado com as propriedades acima, e build/testes foram repetidos antes
da ativação do candidato correto.

## Validação e operação

- `dotnet restore Sufficit.Identity.sln -p:Configuration=Release --force-evaluate`
  com VersionSuffix fixado: 17 projetos, sem erros/avisos.
- `dotnet build Sufficit.Identity.sln -c Release --no-restore`:
  17 projetos, zero erros/avisos.
- `dotnet test src/tests/Sufficit.Identity.Tests.csproj -c Release --no-build
  --no-restore --filter 'FullyQualifiedName~Ui|FullyQualifiedName~DocumentationContractTests'`:
  189 testes aprovados.
- `helpers/package-release.sh`: árvore limpa, revisão exata, assets SUI presentes,
  sem appsettings/certificados no arquivo distribuído.
- `helpers/prepare-cluster-release.sh`: hashes validados nos três nós;
  quatro arquivos de configuração herdados do release ativo em cada nó.
- `helpers/activate-cluster-release.sh`: lease do cluster e ativação de um nó
  por vez, com verificação final uniforme. Os checks tiveram respostas 502
  transitórias durante o startup; todos se recuperaram dentro da janela
  prevista pelo helper. Não houve rollback.
- Todos os nós: serviço ativo, revisão a9f2f25, `/health` e `/health/ready`
  Healthy; hashes de certificado e JWKS preservados em relação à baseline.
- Certificado SHA-256:
  `5e858b8d138993436730db83743ac67183495e44de8e2e041e72b2882410eefb`.
- JWKS SHA-256:
  `85d43862afae2e2eea21c6668aa9ec34fa0c029ac906cd0eaee9122847aed769`.
- Login público `https://identity.sufficit.com.br/account/login`: HTTP 200.
- Discovery OIDC público: HTTP 200.
- `/_content/Sufficit.Blazor.UI/sufficit-ui.css`: HTTP 200, 54.744 bytes.

Não houve mudança de schema nem execução de migrations. As configurações,
certificados e locks versionados foram preservados. Os dois worktrees
isolados desta tarefa foram removidos; artefatos e logs locais ficaram em
`/tmp/identity-sui-deploy-20260908` para rastreabilidade.

Validação operacional concluída em 2026-09-09 00:38 UTC
(2026-09-08 21:38 America/Sao_Paulo). Não foi executado um fluxo autenticado
com conta de usuário nesta entrega.
