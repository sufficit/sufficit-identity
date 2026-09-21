# Entrega do cadastro com continuidade de login

## Objetivo e estado inicial

Executar `commit + push + merge + deploy`, conforme autorização explícita do usuário, para as alterações descritas em [cadastro/login](202609211536-registration-signin.md) e no [diagnóstico inicial](202609211513-registration-failure.md). Esses dois registros descrevem o estado anterior à publicação; este relatório registra a entrega em produção.

O trabalho iniciou em `main`, sobre `a92e68b`, com apenas as alterações desta tarefa. Os três servidores estavam saudáveis na release `20260921T150010Z-9689731`, com o mesmo certificado persistente. Nenhuma conta real foi criada ou modificada durante a entrega.

## Versionamento e validação

- Commit funcional: `63c2e8511cc720b52a85b0383a4179725d41a1cd`, branch `fix/registration-signin-continuation`, enviado ao origin.
- [PR #79](https://github.com/sufficit/sufficit-identity/pull/79) integrado por merge em `68754ceac37101e22e2d957fc71c4638d7dbee36`, com o main local sincronizado.
- Passe local final: **202 testes direcionados aprovados, zero avisos**; `node --check` e `git diff --check` aprovados.
- [CI do PR](https://github.com/sufficit/sufficit-identity/actions/runs/35640156517): **1.583 testes aprovados, 1 ignorado, zero falhas**. Compilação com avisos como erros, contêiner de produção, cobertura e ensaios de migrações, smoke API-only, gitleaks e auditoria de dependências aprovados; nenhum advisory High/Critical.
- [CodeQL do PR](https://github.com/sufficit/sufficit-identity/actions/runs/35640156425) aprovado antes do merge.
- [CI do commit integrado](https://github.com/sufficit/sufficit-identity/actions/runs/35640750733) também aprovado, com os mesmos totais de testes.

## Artefato e decisões operacionais

Publicação executada:

```sh
rtk dotnet publish src/server/Sufficit.Identity.Server.csproj -c Release -o publish-registration-68754ce -warnaserror
```

Publicação aprovada, usando o SUI local limpo `cf71a685cedf1cf5e2e8f1dd0136fb571acbc38b`, conforme `DEPLOY.md`. O restore alterou lockfiles pelo modo local. A regeneração em modo pacote encontrou uma versão NuGet mais recente; essas alterações geradas foram descartadas para manter os lockfiles aprovados no CI. O artefato publicado permanece com o SUI local exigido.

- Release: `20260921T184913Z-68754ce`.
- SHA-256 do arquivo comprimido: `af33a802dfc7f87b58f6c3b9fb545c28aa47f761806062425a9675ca95b9acde`.
- `release-source.json` registra os commits do Identity/SUI; `release-files.sha256` verifica os 334 arquivos publicados.
- Configurações e certificados não foram incluídos no artefato. Cada candidato recebeu os arquivos persistentes e helpers da release ativa daquele servidor.
- Foi utilizado o helper versionado `activate-release.sh`, idêntico ao instalado, conforme o runbook: trava de concorrência, troca atômica e rollback automático. O `deploy.py` genérico não implementa esses controles e não foi utilizado.
- `sufficit-identity-migrator.service` executado uma única vez em eveo-apps antes da primeira troca: `Result=success`, `ExecMainStatus=0`. Esta entrega não contém diferenças de migrations em relação à versão anterior.
- O helper recebeu 502 transitórios enquanto cada processo inicializava e alcançou saúde dentro de seu prazo normal. Nenhum rollback foi necessário. A release anterior permanece disponível.

## Produção

Deploy executado sequencialmente: eveo-apps, apoint-apps, castrum-apps. A validação de um nó terminou antes do início do próximo.

| Nó | Release | Serviço | Liveness/readiness | Reinícios automáticos |
| --- | --- | --- | --- | --- |
| eveo-apps | `20260921T184913Z-68754ce` | active/running | Healthy | 0 |
| apoint-apps | `20260921T184913Z-68754ce` | active/running | Healthy | 0 |
| castrum-apps | `20260921T184913Z-68754ce` | active/running | Healthy | 0 |

Em cada nó, foram verificados o manifesto completo do artefato, a preservação byte a byte das configurações/certificados, `/health`, `/health/ready`, discovery, cadastro, login com `login_hint` e o JavaScript servido igual ao artefato. Os dois `kid` OIDC permanecem iguais nos três nós: `EE50568EDD6249CF7CF3530C14613291EADA5FBC` e `2D649E07373B7D35B890BD5FE732934522D56F5C`. Nenhum evento de nível error foi encontrado no journal do serviço desde a implantação até a verificação final.

O endpoint público `https://identity.sufficit.com.br/health/ready` retornou Healthy. O navegador real, acessando o domínio público sem interceptação de assets, verificou e-mail preenchido, senha vazia, aviso informativo de acesso externo, botão Google, helper JavaScript novo, formulário de cadastro hidratado, antiforgery e checkbox reCAPTCHA visível. A tela mobile de 390 px não apresentou overflow horizontal nem exceções JavaScript; screenshots foram inspecionadas. O JS possui `cache-control: no-cache`.

Evidências locais temporárias: `/tmp/identity-registration-public-smoke.cjs`, `/tmp/identity-registration-public-login.png`, `/tmp/identity-registration-public-register.png`, `/tmp/identity-registration-deploy.json` e scripts de implantação/verificação na mesma pasta. Navegadores encerrados após os testes.

## Limites

Não foram submetidos login/cadastro de clientes nem executado OAuth real com Google/Facebook em produção. Os cenários de senha, MFA, bloqueio e vinculação foram cobertos pelos testes isolados; a validação em produção foi de implantação e navegação. Nenhum e-mail ou mensagem foi enviado.

Este relatório é um complemento documental à release executável `68754ce`; não exige nova publicação de binários. O plano temporário foi encerrado com suas evidências preservadas aqui, sem referências externas pendentes.
