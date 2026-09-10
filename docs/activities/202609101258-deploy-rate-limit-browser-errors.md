# Publicação de rate limit por operação e erros humanos

Publicação solicitada pelo usuário e concluída nos três nós em 10/09/2026. Inclui a implementação testada de rate limit/tela 429 e a evolução anterior de snapshots. NATS permanece desabilitado, confirmado nos arquivos de configuração e ambiente efetivo dos três processos. A reconciliação usa consulta de revisão; não houve alteração de configuração produtiva.

## Artefato

- Publish Release com SUI local: `rtk dotnet publish src/server/Sufficit.Identity.Server.csproj -c Release -o /tmp/identity-rate-production-20260910 -v quiet`, concluído.
- Pacote: `/tmp/identity-rate-production-20260910.tar.gz`, 11120704 bytes; configurações appsettings e certificados excluídos.
- SHA256 pacote: `14759bc0cabcefe87da5c427a1382fc4704feefb6a678dc8137579d790550894`.
- SHA256 `Sufficit.Identity.Server.dll`: `aea7d681374a8dc81af318916db17c355b621f980aca1206b585b2803771ac2d`, conferido nos três nós.
- Fonte: checkout com mudanças autorizadas ainda sem commit; identificação exata pelo hash do artefato. Sem nova migração de banco: tabela de proxies já publicada anteriormente.
- Testes da implementação antes da publicação: 1.173 aprovados, além de Chrome PT/EN desktop/mobile. Locks regenerados em modo pacote após publish, sem erros.

## Publicação e proteção

Diretórios ativos comuns são incompatíveis com os antigos wrappers por symlink. Utilizado staging validado como no deploy anterior, com locks local e remoto de cluster (coordenador eveo), lock por serviço, troca sequencial e rollback automático do nó e dos nós anteriores em caso de falha. Não ocorreu rollback.

Configurações, certificados e helpers preservados. Hashes de configurações/certificados comparados antes de cada troca e depois da ativação. Backup nos três nós: `/opt/sufficit-identity.before-rate-20260910T1555Z`.

| Nó | Serviço iniciado BRT | PID | Readiness | Reinícios automáticos |
| --- | --- | --- | --- | --- |
| eveo-apps | 12:56:11 | 2400961 | Healthy | 0 |
| apoint-apps | 12:56:18 | 3480485 | Healthy | 0 |
| castrum-apps | 12:56:22 | 94696 | Healthy | 0 |

## Verificação efetiva

Em cada processo, probes locais pelo socket, com IPs reservados `198.51.100.231/232` e dois saltos confiáveis, demonstraram:

- 30 POSTs inválidos de token retornam 400; o próximo retorna 429 JSON com `temporarily_unavailable` e `Retry-After`.
- Depois de esgotar token, introspecção e confirmação do dispositivo continuam fora de 429.
- Após esgotar a cota interativa com formulários inválidos sem credenciais, `/connect/device` devolve HTML 429 em português/inglês para navegação, e JSON 429 para APIs.
- Outro IP mantém a própria cota de token. Nenhuma conta, credencial ou usuário real usado nos probes.
- Readiness via socket, discovery via TLS direto em cada nó e discovery público aprovados; issuer correto. JWKS uniforme: SHA256 canônico `7ea30e14bf9c37f747ceac9257d7469108a5ba74fc8505479ce8d925fe322ad5`.
- Snapshot inicial em cada nó: cinco redes confiáveis e dois saltos. Nenhuma falha de refresh, exceção não tratada ou erro crítico na janela pós-publicação inspecionada. Zero rejeições reais de rate limit nessa amostra breve, excluindo probes; isso não garante ausência futura de 429.

Logs locais do procedimento: `/tmp/identity-rate-rollout.log` e `/tmp/identity-rate-postcheck.log`. Script de ativação: `/tmp/identity-rate-rollout.py`, com script remoto `/tmp/identity-rate-remote.py`.

## Rollback

Sob exclusão de deploy concorrente, parar somente `sufficit-identity` no nó, mover o diretório atual para um novo caminho de diagnóstico, restaurar o backup para `/opt/sufficit-identity`, iniciar o serviço e conferir readiness/discovery antes de alterar outro nó. Manter o schema aditivo e a correção existente dos cabeçalhos HAProxy.

## Referências

- [Contrato de cotas e apresentação](../networking/USAGE-RATE-LIMITING.md).
- [Implementação de erros e cotas](202609101251-rate-limit-browser-errors.md).
- [Implementação anterior de snapshots](202609101227-trusted-proxy-nats-synchronization.md).

Publicação concluída. Ativação operacional de NATS continua pendente no plano de padronização, pois requer configuração própria.
