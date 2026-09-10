# Snapshots de runtime — Identity

O Identity implementa o [padrão compartilhado Sufficit](../../../sufficit-standard/docs/architecture/ARCHITECTURE-RUNTIME-SNAPSHOTS.md) para proxies confiáveis. Código e testes locais concluídos; configuração do broker e rollout desta evolução ainda pendentes na etapa 1 do [plano de adoção](../../../sufficit-standard/docs/plans/PLAN-RUNTIME-SNAPSHOTS-ADOPTION.md).

## Contrato implementado

- [TrustedProxySnapshotStore](../../src/core/Networking/TrustedProxySnapshotStore.cs): carga inicial, consulta de revisão isolada, troca imutável, aplicação após commit sem releitura e serialização com refresh concorrente.
- [Serviço administrativo](../../src/management/Networking/TrustedProxyManagementService.cs): configuração e auditoria na mesma transação; falha da notificação não transforma gravação confirmada em erro de save.
- [Bridge NATS](../../src/server/TrustedProxyNatsBridge.cs): credencial/configuração externa, assinatura por instância, conexão inicial e reconexão com tentativas, envelope limitado e invalidação sem conteúdo autoritativo.
- [Worker](../../src/server/TrustedProxyRefreshWorker.cs): agrupamento de avisos, retries limitados para visibilidade da revisão e reconciliação periódica para notificações ausentes ou superadas.
- [Middleware](../../src/server/TrustedProxyForwardingMiddleware.cs): atendimento em memória, dois saltos com confiança validada, resposta restritiva 503 ao ultrapassar frescor.

As redes continuam sendo mescladas por host; o override de saltos segue o contrato existente. A revisão GUID não é ordenada. O banco local define o conteúdo aplicado, com convergência eventual dependente da replicação. Não há outbox nem confirmação remota por nó.

## Política de frescor e operação

Mantido padrão de 30 segundos para conferir somente a revisão, sem baixar novamente a lista. Máximo de 120 segundos sem confirmar o banco; falhas posteriores fazem as requisições receberem 503 até recuperação. Aumentar para cinco minutos exige tolerância compatível e avaliação do atraso de remoção de confiança.

NATS fica desabilitado até configuração operacional explícita. O [guia de proxies](../networking/USAGE-TRUSTED-PROXIES.md) descreve opções, diagnóstico, limitações e testes com broker isolado. O teste de integração exercita três instâncias, notificação antes de replicação, falha inicial do broker, aviso perdido e reconexão.
