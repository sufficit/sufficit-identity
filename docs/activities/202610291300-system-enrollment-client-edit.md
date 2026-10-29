# Edição de clientes com grant nativo de habilitação
Documentação lida: PRODUCT, USAGE-SYSTEM-USERS, skill temporary-management-token,
DEPLOY e RUNBOOK-CLUSTER-ROLLING-DEPLOY.
O grant nativo era aceito pelo STS, mas recusado pelo editor e validador compartilhado.
Ambas as formas (URN e prefixo gt:) agora são aceitas; ept:token é derivado.
Limites de origem e grants desconhecidos permanecem sujeitos às políticas existentes.
Três regressões falharam antes da correção. Após: 83 testes direcionados e
1932 testes não-browser passaram. Build Release: zero erros, avisos NU1902
preexistentes sobre MySqlConnector 2.5.0.
O SUI foi compilado do checkout local isolado e limpo (e6fc289), evitando colisão
de arquivos intermediários do checkout compartilhado. Lockfiles não alterados.
Publicação e validação operacional pendentes no plano.

O CI recusou NU1902; MySqlConnector foi fixado em 2.6.2 com referência direta no Core e lockfiles atualizados, sem silenciar auditoria. Referência: https://github.com/advisories/GHSA-473q-m89c-ghf8.
Nova validação: build Release -warnaserror com zero avisos/erros; 1932 testes passaram e 2 foram ignorados pelas condições existentes.
Preparação operacional preservou os binários anteriores em diretório de rollback e converteu o caminho ativo em symlink nos dois nós disponíveis, sob locks de cluster/host. Saúde e hashes dos binários permaneceram iguais.

## Publicação verificada
Código publicado: bfaf3415b1ffc01a956316b60754fe5228a7c543. CI [40900832978](https://github.com/sufficit/sufficit-identity/actions/runs/40900832978) e CodeQL passaram, incluindo navegador, contêiner, integração MariaDB e auditorias.
Pacote SHA-256: 96f3a2045a5c12e90af7b55c6bfc68d20d28228ce2eb57a3e1c8737f30e1ed18.
Ativação sequencial pelo wrapper do cluster concluída nos dois nós ativos; ambos service=active, health=Healthy, ready=Healthy, mesma revisão, certificado e JWKS. Sem alteração de schema.
A recuperação do consumidor permanece pendente: token temporário expirado (HTTP 401), exigindo novo token antes de editar o scope pela API. Nenhuma permissão ou credencial do consumidor foi alterada nesta publicação.
