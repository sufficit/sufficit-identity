# Configuração de proxies confiáveis no Management

## Objetivo e estado inicial

Tráfego cliente → proxy → Nginx → Identity ficava atribuído ao proxy: o middleware processava apenas um salto. A lista estava exclusivamente em appsettings, sem edição pelo Management.

## Entrega

- Tela `/management/settings/trusted-proxies`, acessível por Configurações e navegação, com origens Arquivo/Banco, edição IPv4/IPv6/CIDR e limite de saltos opcional.
- Contrato e API `/api/trusted-proxies` protegidos por capabilities próprias (`identity.trusted-proxies.read` e `.manage`) e pela política MFA existente. Permissões com descrições pt-BR/en-US.
- Linha singleton no banco com revisão para concorrência otimista. Mesclagem aditiva preserva o baseline do arquivo; limite do banco sobrescreve o arquivo, quando informado. Padrão: dois saltos.
- Configuração e auditoria antes/depois gravadas atomicamente. A auditoria existente exibe os valores e identifica o operador/correlação.
- Snapshot imutável carregado antes do tráfego, atualizado após salvar e a cada 30 segundos nas demais instâncias após replicação. Nenhuma consulta ao banco no encaminhamento HTTP. Falha inicial impede startup; falha de atualização preserva o último estado válido e é registrada.
- Middleware reutilizado por versão do snapshot, sem modificar opções em uso por requisições concorrentes. Testes incluem Unix socket (IP do peer nulo), IPv4 mapeado, IPv6, dois saltos e parada em peers não confiáveis.
- Migração EF `20260910131719_AddTrustedProxyConfiguration`, delta SQL `097-add-trusted-proxies.sql` e schema vazio canônico atualizados.

## Validação executada

- `dotnet build` e `dotnet publish` do host .NET 10 concluídos sem erros.
- Suíte inicial: 1.132 testes passaram. Após acrescentar dois casos de segurança, suíte de 1.134 casos: 1.133 passaram e o novo nome de documento violou a convenção. Corrigido para `USAGE-TRUSTED-PROXIES.md`; ambos os testes de documentação passaram na revalidação.
- Rodada dirigida final: 83 testes de proxies, arquitetura da UI, schema e localização passaram. Os 18 casos de proxies cobrem normalização/rejeição, mesclagem, auditoria/rollback, revisão obsoleta, atualização de outra instância, ausência de consultas por request, autorização e MFA.
- MariaDB 10.4.34 em container isolado: migração real aplicada pelo host; health/ready 200; contrato canônico do banco passou com 35 tabelas.
- Playwright contra host local com banco isolado: cadastro IPv4/IPv6, origens mescladas, recarga, rejeição de /0 e auditoria antes/depois com operador conferidos. Tela 1440×1000 e 390×844 sem overflow horizontal. Ajustados padding dos painéis e apresentação secundária de Recarregar.
- Artefatos visuais locais: `/tmp/identity-proxies-desktop.png` e `/tmp/identity-proxies-mobile.png`; logs de automação em `/tmp/identity-proxy-browser-evidence`.
- `git diff --check` passou. Ambiente temporário de execução encerrado; arquivos fonte preservados para revisão.

## Publicação e limites

Nenhum deploy, commit, push ou mudança de banco de produção foi executado. A migração deve preceder os novos binários, uma vez no banco replicado. O proxy de borda deve substituir headers de encaminhamento não confiáveis antes de informar o IP original; a mudança no Identity não altera o HAProxy/Nginx externos. Arquivos de configuração são lidos no startup, enquanto alterações do Management se propagam sem reinício.

Referência permanente: [uso e publicação](../networking/USAGE-TRUSTED-PROXIES.md).
