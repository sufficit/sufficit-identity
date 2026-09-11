# Deploy da capability de confirmação de usuários

Em 11/09/2026 foi publicada a renomeação para `identity.users.confirmation`,
com compatibilidade de leitura para o identificador antigo. Commit de aplicação:
`03243f37748f1332eacccf5405147d3db3cc0155`, publicado em main.

## Preparação e escopo

A produção estava uniforme em `58902d004c440977a12c35fa4b41e6b3782ee8f0`.
Não havia migrations novas. Foi criado um checkout isolado do Identity e usado
o SUI local no commit `3d84927b5730dc8f669412c97491a7b4e81675b7`, também em checkout
limpo. Alterações concorrentes em Directory.Packages.props e CSS do SUI foram
preservadas e não entraram no artefato.

Os wrappers de releases exigem um layout por symlink que os servidores ainda
não usam. O layout físico existente foi mantido, com preparação em diretório
separado, trava local e lease na trava de cluster do eveo, trava por nó,
ativação sequencial e rollback dos nós alterados se qualquer etapa falhasse.
Configurações, certificados e helpers vieram do diretório ativo de cada nó.

## Artefato e validação

- Release: `20260911T225636Z-03243f3-r2` (mesmo pacote; segunda preparação).
- Arquivo: `20260911T225636Z-03243f3.tar.gz`, 335 arquivos.
- SHA-256 do pacote: `508cd03a0827f64fcc938231810e97ee8d16185c515474a8d1d0bdbe388b56bd`.
- SHA-256 de Sufficit.Identity.Application.Abstractions.dll: `7f22f93ea5997f3c55e08dc7f8299b99be847b1e932bf8d1b224cc8eff9c4e0b`.
- 50 testes direcionados aprovados no checkout isolado com o SUI local.
- [CI 34656103266](https://github.com/sufficit/sufficit-identity/actions/runs/34656103266): 1.212 testes aprovados, 1 ignorado, zero falhas; build com warnings-as-errors, container e demais gates aprovados.
- [CodeQL 34656103232](https://github.com/sufficit/sufficit-identity/actions/runs/34656103232): concluído com sucesso.

## Intercorrência e correção

A primeira tentativa ativou eveo, mas o prestart de apoint recusou a cópia do
certificado porque a preparação havia aplicado o proprietário dos binários ao
arquivo, que precisa de root:www-data. O rollback automático restaurou a revisão
anterior em apoint e eveo; castrum não chegou a ser ativado. Os três nós foram
verificados saudáveis antes da nova tentativa.

A preparação foi corrigida para preservar e comparar conteúdo, UID, GID e modo
dos arquivos persistentes antes de parar o serviço. A segunda tentativa usou
candidatos novos com sufixo r2 e passou nos três nós.

## Resultado em produção

| Servidor | Ativação (Brasília) | PID | Restarts |
|---|---|---|---|
| eveo-apps | 20:00:06 | 3967388 | 0 |
| apoint-apps | 20:00:15 | 1407338 | 0 |
| castrum-apps | 20:00:20 | 1073554 | 0 |

Todos executando `03243f3`, health/ready saudáveis, discovery com issuer esperado,
certificados e JWKS iguais ao estado anterior e entre os nós. O assembly em cada
nó corresponde ao pacote e contém o novo identificador. Logs da invocação atual
sem falhas de inicialização, erros críticos ou exceções não tratadas.

Verificação final executada:

```sh
IDENTITY_SSH_KEY=/home/hugodeco/.ssh/id_ed25519_sufficit helpers/verify-production-cluster.sh 03243f37748f1332eacccf5405147d3db3cc0155
```

Backup anterior preservado em cada nó:
`/opt/sufficit-identity.before-confirmation-20260911T225636Z-03243f3-r2`.
Nenhum grant, configuração ou histórico de auditoria foi reescrito.
