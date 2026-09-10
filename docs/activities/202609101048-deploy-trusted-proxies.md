# Deploy de proxies confiáveis — 10/09/2026

## Entrega

Deploy solicitado explicitamente pelo usuário, concluído em eveo-apps, apoint-apps e castrum-apps. Interface `/management/settings/trusted-proxies` publicada com persistência em banco, auditoria antes/depois, mescla com appsettings e snapshot em memória atualizado a cada 30 segundos. Processamento de dois saltos com validação das redes confiáveis.

## Estado inicial e decisões

- Serviços ativos em diretórios comuns `/opt/sufficit-identity`, incompatíveis com os antigos auxiliares de releases por symlink. Usado staging próprio, troca sequencial e backup mantido.
- HAProxy tinha `option forwardfor if-none`, preservando cabeçalhos enviados pelo cliente. Antes de ativar dois saltos, adicionado somente ao backend Identity `http-request set-header X-Forwarded-For %[src]`, nos três proxies. Gerador, config.json e arquivos gerados atualizados no repositório sufficit-services-haproxy.
- Configurações e certificados preservados byte a byte. Cinco redes de appsettings mantidas, incluindo 172.16.0.0/16, que contém 172.16.2.0. Banco inicia sem redes adicionais e sem override do limite; o padrão efetivo é dois saltos.
- Migração aditiva executada apenas em eveo-apps, usando o novo artefato `--migrate-only` com identidade e ambiente do serviço de produção, sem iniciar servidor HTTP. O migrator antigo apontava para o binário anterior.

## Artefato e migração

- Publish: `dotnet publish src/server/Sufficit.Identity.Server.csproj --no-restore -c Release -o /tmp/identity-proxy-production-20260910 -v quiet`, exit 0, usando o projeto SUI local.
- Artefato: `/tmp/identity-proxy-production-20260910.tar.gz`, 10852430 bytes.
- SHA256 do pacote: `c1ae545394f209f6047f8f94c57c0813cd5774ece5625e6717f14cd12251b488`.
- SHA256 de Sufficit.Identity.Server.dll: `7f7de927f73f017e190c83d16db458043a17754a810b269ee3158d867b719687`, conferido nos três nós.
- Migração `20260910131719_AddTrustedProxyConfiguration` confirmada em bancos distintos: eveo-data, apoint-data, castrum-data. Nova tabela, linha singleton e colunas beforejson/afterjson presentes em todos.
- Conta da aplicação não permite consultar SHOW ALL SLAVES STATUS; convergência do schema confirmada diretamente em cada banco, sem afirmar uma medição do lag.
- Log de migração em eveo-apps: `/var/log/sufficit-identity-migration-proxies-20260910.log`, permissão 0600.
- Fonte local baseada em `162a459`, com alterações da implementação ainda não commitadas; o identificador exato do deploy é o hash do artefato acima.

## Ativação e verificações

| Instância | Ativação BRT | Saúde | Reinícios |
| --- | --- | --- | --- |
| eveo-apps | 10:44:19 | Healthy | 0 |
| apoint-apps | 10:45:00 | Healthy | 0 |
| castrum-apps | 10:45:27 | Healthy | 0 |

- HAProxy: `haproxy -c -f <candidate>` e reload sequencial aprovados nos três proxies. Gerador: `python3 -m unittest discover -s tests`, 10 testes passaram, incluindo substituição explícita por aplicação.
- Snapshot de cada aplicação: revision initial, cinco redes, dois saltos. Sem erros de atualização ou exceções não tratadas na janela observada.
- Readiness pelo socket Unix, discovery HTTPS direto na porta 26501, discovery público e discovery passando individualmente pelos três proxies: válidos. Issuer correto `https://identity.sufficit.com.br/`.
- Rota de management publicada e protegida: resposta 302 para cliente sem sessão. Fluxo autenticado de salvar/validar/auditar foi testado localmente durante a implementação; não foi criada sessão administrativa em produção para este deploy.
- Teste de comportamento no processo real de cada nó: POST para rota inexistente `/connect/__deployment_proxy_probe_20260910`, via socket local, com X-Forwarded-For `198.51.100.241, 172.16.2.0` e esquema HTTPS. Primeiras 30 respostas 404, 31ª 429; log identifica 198.51.100.241. Uma requisição do segundo IP reservado 198.51.100.242 retorna 404, comprovando cota independente. Nenhuma credencial ou usuário real foi usado nesses probes.
- Logs reais após publicação em eveo-apps também mostram limitação por IPs distintos, sem ocorrências de rate limit para 172.16.2.0 na amostra. Ainda ocorreram 429 para origens reais, principalmente `/connect/introspect` originado no próprio eveo-apps. A cota de 30/minuto permanece inalterada; este deploy não elimina sobrecarga legítima por origem.
- `git diff --check` aprovado nos dois repositórios.

## Rollback e arquivos preservados

- Backup dos binários/configurações em cada servidor: `/opt/sufficit-identity.before-proxies-20260910T1342Z`.
- Para rollback de um nó: parar sufficit-identity, mover o diretório atual para um novo nome de diagnóstico, restaurar o backup para `/opt/sufficit-identity`, iniciar e verificar readiness/discovery antes de prosseguir para outro nó. Manter o schema aditivo; não executar downgrade automático.
- Backups HAProxy: eveo `/etc/haproxy/haproxy.cfg.before-proxies-20260910T134225Z`, apoint `...20260910T134233Z`, castrum `...20260910T134255Z`. A correção de cabeçalho pode permanecer com o binário anterior. Para restaurar configuração, validar sintaxe antes de reload.
- Relatório da implementação: `docs/activities/202609101034-trusted-proxies-management.md`.
- Contrato de uso: `docs/networking/USAGE-TRUSTED-PROXIES.md`.
