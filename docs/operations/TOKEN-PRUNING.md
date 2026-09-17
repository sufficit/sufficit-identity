# Limpeza centralizada de tokens

O Server é o único executável; o STS fornece a operação de limpeza. O comando
`--prune-tokens` compõe somente banco e OpenIddict, sem HTTP, provisionamento,
migrações ou outros workers. Tokens válidos continuam protegidos pelas regras
oficiais do OpenIddict. Retenção: 30 dias. Tokens são tratados antes das
autorizações órfãs; uma falha pode deixar trabalho parcial, repetível com segurança.

## Produção atual

Castrum é o único proprietário do agendamento para o banco multimaster replicado.
Instalar `helpers/sufficit-identity-pruning-api.conf` em
`/etc/systemd/system/sufficit-identity.service.d/token-pruning.conf` em **todos**
os servidores e reiniciar cada API sequencialmente. Só depois habilitar no Castrum
as quatro unidades `helpers/sufficit-identity-pruning{,-watchdog}.{service,timer}`.
Não ativar esses timers em Eveo/Apoint. Não usar GET_LOCK como trava entre réplicas:
essa trava pertence à instância MariaDB, não ao conjunto replicado.

Agendamento às 00/06/12/18 UTC, com até cinco minutos de dispersão e recuperação
após reinício. O systemd não sobrepõe a mesma unidade. Prazo cooperativo de 30 min,
limite externo de 35 min e 30 s para encerramento. O comando também mantém uma
trava de arquivo no diretório de estado; não é uma trava distribuída entre máquinas.

`/var/lib/sufficit-identity-maintenance/token-pruning.json` registra timestamp UTC e
contagens **somente após ambas as etapas terem sucesso**, inclusive zero exclusões.
A gravação usa substituição atômica; falhas conservam o último sucesso.
O watchdog roda a cada hora, sem conexão ao banco nem acesso a seus segredos.
Ausência, corrupção ou idade superior a 14 h emite `TokenPruningOverdue` em nível
Warning e termina com código 1, deixando a unidade com falha. A próxima execução
saudável retorna 0. O atraso máximo até o alerta é aproximadamente 15 h.

```sh
systemctl start sufficit-identity-pruning.service
systemctl start sufficit-identity-pruning-watchdog.service
journalctl -u sufficit-identity-pruning -u sufficit-identity-pruning-watchdog
systemctl list-timers 'sufficit-identity-pruning*'
```

Logs locais não detectam a queda completa do Castrum: a disponibilidade do host
precisa de monitoramento externo. Para transferir o agendamento, desabilitar os
Timers antigos, aguardar/interromper a execução, copiar o estado e só então ativar
o novo proprietário. Não reativar o worker das APIs durante essa troca.

## Kubernetes

Usar a mesma imagem do Server e argumentos `--prune-tokens` / `--check-token-pruning`.
O exemplo `helpers/kubernetes/token-pruning.yaml` tem um CronJob de limpeza e outro
de verificação. Há **um proprietário por conjunto de dados**, mesmo com vários
clusters. Desativar os timers no Castrum antes de ativar o CronJob e manter
`Sufficit__Identity__TokenPruning__RunInWebHost=false` em todos os Deployments da API.

A imagem e os nomes de Secret/PVC são parâmetros do ambiente; o exemplo inicia
suspenso. O PVC precisa persistir entre Jobs e permitir acesso pelos dois CronJobs
(RWX ou provisionamento compatível). O arquivo é apenas o registro operacional,
não uma coordenação global. `concurrencyPolicy: Forbid` vale por CronJob e não
oferece execução exatamente uma vez; a operação permanece idempotente.
Também é possível alertar externamente sobre `lastSuccessfulTime` do CronJob,
o que cobre a falha do executor. Não criar uma segunda agenda para o mesmo banco.

Referência: [CronJobs do Kubernetes](https://kubernetes.io/docs/concepts/workloads/controllers/cron-jobs/).
