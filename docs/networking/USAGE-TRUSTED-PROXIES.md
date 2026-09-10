# Proxies confiáveis

A tela `/management/settings/trusted-proxies` e a API `GET/PUT /api/trusted-proxies` usam o mesmo serviço administrativo. A leitura exige `identity.trusted-proxies.read`; a escrita, `identity.trusted-proxies.manage`, além da política MFA do Management. O prefixo HTTP acompanha a configuração do módulo.

## Mesclagem e aplicação

`Sufficit:Identity:TrustedProxies` permanece como baseline de arquivo. O banco contém redes adicionais, normalizadas e sem duplicatas, na linha singleton de `trustedproxyconfiguration`. Remover uma rede do banco nunca remove uma entrada igual do arquivo. A tela mostra ambas as origens.

`Sufficit:Identity:ForwardLimit` vale 2 por padrão. O valor opcional no banco tem precedência; a opção “Usar o limite de saltos do appsettings” remove essa sobrescrita. Os limites aceitos são de 1 a 10. IPs IPv4/IPv6 e redes CIDR são aceitos; redes universais `/0`, nomes DNS e endereços com escopo são rejeitados. CIDRs com bits de host são normalizados para a rede base.

O host carrega o snapshot antes de aceitar tráfego, após as migrações. Uma falha inicial impede a inicialização. O worker consulta somente a revisão a cada 30 segundos por padrão, com variação de ±10%; o conteúdo completo só é lido na inicialização ou quando a revisão mudou. Uma confirmação sem mudança renova o frescor e mantém a mesma instância do snapshot.

A gravação administrativa e o refresh compartilham coordenação: após o commit, os dados confirmados são aplicados diretamente na memória, sem outro SELECT. Uma recarga iniciada antes da gravação não pode sobrescrevê-la. A notificação é enviada somente após o commit. Arquivos são carregados no início do processo e exigem reinício quando alterados.

O middleware captura uma instância imutável das opções por versão do snapshot. Não modifica listas usadas por requisições concorrentes nem consulta o banco durante o encaminhamento. Cada salto deve ser confiável, e o processamento para ao encontrar um intermediário não confiável.

## Auditoria e concorrência

Configuração e evento de auditoria são gravados no mesmo SaveChanges/transação. Os campos `beforejson`/`afterjson` contêm somente as redes e o limite configurados no banco, visíveis em “Ver alteração” na auditoria. Ator, data, capability e correlação seguem o contrato existente. A revisão enviada pela tela evita sobrescrever uma alteração concorrente; em conflito, recarregue antes de salvar.

## Publicação

Aplicar `20260910131719_AddTrustedProxyConfiguration` uma vez no banco antes de trocar os binários. Alternativamente, o SQL `docs/migration/sql/097-add-trusted-proxies.sql` aplica esse delta uma vez; não executar ambos sem verificar o histórico. O schema vazio canônico também foi atualizado. A migração cria a linha inicial e adiciona campos opcionais à auditoria, preservando os dados existentes.

Na cadeia cliente → proxy → Nginx → Identity, o header deve chegar ao Identity com `IP_CLIENTE, IP_PROXY`. O proxy de borda precisa substituir headers encaminhados fornecidos por clientes não confiáveis; apenas confiar no IP do proxy não autentica um header que ele copiou sem validar. Não aumentar o número de saltos sem verificar esse comportamento. O teste da aplicação cobre o limite e a parada em peers não confiáveis; não modifica nem substitui a configuração do proxy externo.

## Sincronização por NATS e recuperação

Implementada conforme a [arquitetura de snapshots](../architecture/ARCHITECTURE-RUNTIME-SNAPSHOTS.md). NATS é opcional e desabilitado por padrão. Sua indisponibilidade não impede salvar a configuração; a API informa `NotificationPending` quando o último commit local não conseguiu enviar o aviso. Esse campo não é confirmação de aplicação pelos demais nós. `NotificationsConnected` indica conexão do transporte.

Cada instância assina sem queue group. O aviso contém versão do envelope, identificador do evento/processo, domínio, escopo, revisão e horário; não transporta redes confiáveis. A assinatura usa por padrão `sufficit.<ambiente em minúsculas>.identity.trusted-proxies.changed.v1` (por exemplo, `sufficit.production.identity.trusted-proxies.changed.v1`). Todos os nós devem alcançar o mesmo domínio NATS e subject, com credenciais e permissões restritas. A conexão aceita URL `nats://` ou `tls://`; usar TLS conforme a rede e política operacional.

Ao conectar ou reconectar, a assinatura é confirmada antes de solicitar uma conferência do banco. A bridge repete tentativas mesmo quando a conexão inicial falha. Avisos são agrupados em uma fila de capacidade 1; uma rajada não cria uma fila ilimitada. Há um debounce de 100ms antes da consulta por aviso. Um aviso recebido durante a atualização permanece para a próxima conferência.

Se a revisão anunciada ainda não aparece, há tentativas adicionais após aproximadamente 1, 2, 4, 8, 15 e 30 segundos, com variação de ±10%. Depois dessa janela, a reconciliação periódica continua. GUIDs são opacos: avisos atrasados não ordenam snapshots, e uma revisão antiga já superada não bloqueia o processo indefinidamente. O conteúdo e a revisão aplicados são sempre os retornados juntos pelo banco local.

A convergência é eventual e depende da replicação: uma leitura recente da réplica não prova que ela viu todos os commits de outros servidores. Não há outbox nem confirmação de aplicação por nó. Queda entre commit e publicação, ou evento perdido, é recuperada na conexão/reconciliação. SQL externo que altere a configuração precisa também mudar `revision`; manter a revisão impede detectar a alteração.

## Opções do host

Em `Sufficit:Identity:ProxySynchronization`:

| Opção | Padrão | Comportamento |
| --- | --- | --- |
| `ReconcileSeconds` | 30 | Conferência escalar, intervalo de 1 a 3600 segundos, com ±10% de variação. |
| `MaxStaleSeconds` | 120 | Prazo máximo sem confirmação bem-sucedida do banco; deve ser pelo menos duas vezes o intervalo e no máximo 86400. |
| `RefreshTimeoutSeconds` | 10 | Timeout de cada tentativa do worker, entre 1 e 60 segundos. |
| `Nats:Enabled` | false | Habilita avisos; não modifica a autoridade do banco. |
| `Nats:Url` | nats://127.0.0.1:4222 | Endpoint; configurar o endereço real alcançável pelos nós. |
| `Nats:Token` | ausente | Credencial opcional; fornecer no ambiente protegido do serviço. |
| `Nats:Subject` | derivado do ambiente | Override opcional, sem curingas. |

Exemplo de nomes de variáveis do ambiente protegido: `Sufficit__Identity__ProxySynchronization__Nats__Enabled`, `Sufficit__Identity__ProxySynchronization__Nats__Url` e `Sufficit__Identity__ProxySynchronization__Nats__Token`. Não versionar valores de credenciais. Nenhum segredo é necessário para a reconciliação sem broker.

Para adotar 300 segundos, declarar também uma tolerância compatível (pelo menos 600 segundos) e avaliar o atraso de remoção de confiança. O padrão continua em 30 segundos para não ampliar automaticamente essa janela. Este intervalo não é garantia absoluta de propagação: inclui replicação, variação e duração das tentativas.

## Frescor e diagnóstico

Falhas preservam o último snapshot válido. Quando `MaxStaleSeconds` é excedido, o middleware retorna `503` antes de processar a requisição, inclusive endpoints de saúde/administração; jamais limpa a validação para confiar em qualquer origem. O worker continua trabalhando e a confirmação posterior do banco restabelece o atendimento automaticamente. A readiness também registra a verificação `trusted-proxy-snapshot`.

A API administrativa inclui `LastConfirmedAtUtc`, `Generation`, `IsFresh`, `NotificationsEnabled`, `NotificationsConnected` e `NotificationPending`. `Generation` identifica trocas locais; não é versão global ordenada. No serviço `TrustedProxySnapshotStore.Diagnostics`, contadores de leituras escalares/conteúdo, última troca e falhas consecutivas permitem inspeção e testes. Logs registram conexão, desconexão, falhas, recuperação esgotada e recargas; a conferência bem-sucedida é Debug. Não são registrados URL/token do broker.

## Testes locais com broker dedicado

`TrustedProxySynchronizationTests` valida SQL escalar, commit sem releitura, rollback, concorrência, frescor, entrada inválida e recuperação. `TrustedProxyNatsIntegrationTests` usa três stores independentes, broker autenticado, falha inicial, visibilidade atrasada da réplica e reconexão após aviso perdido.

O teste NATS é opt-in: fornecer `IDENTITY_TEST_NATS_URL` e `IDENTITY_TEST_NATS_CONTAINER`, cujo nome deve começar com `identity-proxy-sync-tests-`. O broker é exclusivamente de teste, com token `identity-test-token`; o teste para/inicia esse container. Mapear uma porta local FIXA, pois portas aleatórias podem mudar em um restart. Nunca apontar essas variáveis para produção. Sem elas, o teste é marcado como skipped.

Esta implementação não exige nova migração além da tabela de proxies já existente. Ativação NATS e publicação desta versão em produção são etapas operacionais separadas.
