# Vault — migração dos consumidores para `ISecretStore`

**Data:** 2026-08-09 09:30  
**Plano:** [`PLAN-VAULT.md`](../plans/PLAN-VAULT.md)  
**Status:** concluído

## Entregue

- O host cria uma única fronteira de startup (`EnvironmentSecretStore`) e a
  aplica antes do bind das opções.
- A conexão do banco, senhas de signing/encryption e credenciais Google,
  GitHub e Facebook são resolvidas por nomes lógicos através de `ISecretStore`.
- O overload de `AddSufficitSecretOverrides` aceita qualquer implementação de
  `ISecretStore`, mantendo a composição testável e sem acoplamento ao ambiente.
- O carregamento de certificados usa a mesma fronteira; não há fallback de
  configuração para rolling deploys.
- Os transportes SMTP e RabbitMQ/Q-EMAIL também resolvem suas senhas por
  `ISecretStore`, com os nomes `identity/smtp/password` e
  `exchange/rabbitmq/password`.
- Cobertura adicionada para o mapeamento de overrides e para o loader de
  certificados e transportes de e-mail; a suíte completa passou com 560 testes
  e 1 teste de UI pulado.

## Operação e limite

Instale os `SUFFICIT_SECRET_*` em todas as réplicas antes de ativar o release.
O startup falha fechado se encontrar um valor legado em `appsettings.*.json`.
O `VaultBackedSecretStore` continua reservado à resolução em runtime: ele não
pode ser usado para o primeiro segredo de conexão, pois o banco é pré-requisito
do próprio store.
