# Plano — sincronizar Identity

1. [concluído] Integrar PRs 50/51/53/58 e alteração local de arquivamento de tokens, revisar locks e validar.
2. [concluído] Commit/push/PR/merge e preparar pacote com SUI local.
3. [em andamento] Implantar nos três nós, validar revisão/saúde/OAuth e registrar.

Raiz original preservada, cópia dos arquivos em cache privado da tarefa. Deploy sequencial pelo procedimento DEPLOY.md.

Validação: 1079 testes + build Release -warnaserror em modo pacote e em modo SUI local (17 projetos). Locks completos regenerados em modo pacote e preservados para CI. SUI fixa em 4bd05529 / VersionSuffix 1.26.908.2020, com boundary local para não herdar CPM do diretório pai. Baseline dos três nós saudável em dc52b2567b1b22b67c120f9699d9f5bb9ba68ffa.
