# Sincronização de proxies confiáveis por NATS

## Entrega

Implementado no Identity o padrão de snapshots para proxies confiáveis. Requisições continuam lendo memória; reconciliação consulta só a revisão e carrega conteúdo quando alterado. Gravações aplicam o estado confirmado diretamente após commit, sem releitura. NATS opcional antecipa recargas nas outras instâncias, com recuperação por revisão.

Fonte inicial: implementação anterior de proxies já presente no checkout, junto aos documentos de padronização. Alterações anteriores preservadas. Esta execução implementou código e testes, sem acessar ou alterar serviços de produção, sem commit/push e sem deploy.

## Mudanças por área

- Core: coordenação comum para refresh/commit; SQL escalar; snapshot imutável; diagnóstico de geração, confirmação, conteúdo/revisão e falhas; opções validadas e publicação desacoplada por interface.
- Management: configuração e auditoria continuam na mesma transação; atualização local após commit; falha do aviso não é retornada como falha da gravação. Contrato expõe conectividade, frescor e aviso pendente.
- Host: NATS.Client 1.1.8 centralizado e pinado nos lockfiles; bridge opcional com assinatura sem queue group, escopo por ambiente, reconexão inclusive após falha inicial, envelope limitado e sem configuração autoritativa.
- Worker: mailbox de capacidade 1, debounce de 100ms, retries 1/2/4/8/15/30s e reconciliação com ±10% de variação. Avisos opacos não ordenam conteúdo nem prendem recuperação indefinidamente.
- Middleware/readiness: sem confirmação do banco além do prazo máximo, responder 503 mantendo confiança validada em memória. Recuperação do banco restaura atendimento.
- Management UI: informa o mecanismo de avisos/conferência e diferencia gravação salva de notificação pendente.
- Documentação: guia operacional e arquitetura local atualizados; piloto do plano comum marcado como implementado/testado localmente, ainda aguardando rollout.

## Decisões e limites

- Padrão de revisão mantido em 30s (±10%), para não ampliar automaticamente o atraso na remoção de confiança; nenhuma lista completa baixada quando a revisão é igual.
- Tolerância de 120s sem confirmação da fonte; timeout de 10s por tentativa do worker. Intervalos configuráveis e validados. Alterar para 300s exige tolerância compatível e avaliação operacional.
- NATS desabilitado por padrão. Ativação requer URL, credencial/permissões e domínio de subject comum aos nós. Configuração do token via ambiente protegido; não logar credencial/URL.
- Revisão GUID é opaca. Leitura recente de uma réplica não comprova visibilidade global. Convergência depende da replicação; retries limitados e reconciliação recuperam avisos ausentes/superados. Sem outbox nem confirmação de aplicação por nó.
- `NotificationPending` descreve falha ao enviar o último aviso local; não é um tracker de convergência do cluster. Publicação aceita pelo cliente NATS não garante que pares já aplicaram.
- Sem nova migração nesta evolução; depende da tabela de proxies da implementação anterior.

## Validação executada

- Build de Sufficit.Identity.Tests: 14 projetos, zero erros e avisos.
- 33 testes direcionados de proxies e contrato de sincronização passaram, incluindo broker real.
- Suíte completa com broker habilitado: **1144 testes passaram**, zero skips e avisos (15,7s na execução registrada).
- Após atualizar documentação: dois DocumentationContractTests passaram.
- Testes SQL comprovaram que revisão inalterada não seleciona/deserializa networksjson e que commit local não gera SELECT posterior.
- Testes cobriram rollback, falha ao publicar, concorrência refresh/commit, rejeição de envelopes, fila limitada, expiração/recuperação de frescor, evento anterior à réplica e aviso fora de ordem.
- Broker NATS 2.14.6 em Docker, imagem nats:2-alpine com digest sha256:ad7a43eb7e3337c3c38ce5d784d1461791f95f730f252d2b25eee699752a0ca3. Três stores/bridges/workers independentes com bancos SQLite; publicação autenticada, falha inicial, réplica atrasada, restart e recuperação de commit sem aviso. Container dedicado removido ao concluir.
- Primeiro ensaio de broker sofreu timeout porque a porta aleatória mudou no restart; corrigido ambiente para porta fixa antes de repetir. Não foi cancelamento manual nem falha funcional ignorada.
- A primeira suíte completa apontou o contrato contra sleeps em testes; substituídos por sinais dos logs, sem relaxar a guarda do repositório.
- Lockfiles regenerados com `dotnet restore Sufficit.Identity.sln --force-evaluate -p:SufficitUseLocalSui=false`: 16 projetos, zero erros/avisos; essa flag foi usada somente para locks, conforme Directory.Build.props. Builds/testes consumiram o SUI local.
- JSON do template, versões nos locks e git diff --check em Identity/Standard aprovados.

## Referências

- [Guia e opções](../networking/USAGE-TRUSTED-PROXIES.md).
- [Arquitetura do piloto](../architecture/ARCHITECTURE-RUNTIME-SNAPSHOTS.md).
- [Plano de adoção e rollout pendente](../../../sufficit-standard/docs/plans/PLAN-RUNTIME-SNAPSHOTS-ADOPTION.md).

Plano temporário desta implementação concluído; rollout continua rastreado no plano comum. Nenhum servidor produtivo recebeu esta versão nesta execução.
