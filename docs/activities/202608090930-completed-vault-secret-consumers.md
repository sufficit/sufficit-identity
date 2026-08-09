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
- O carregamento de certificados usa a mesma fronteira e preserva o fallback de
  configuração apenas para rolling deploys já instalados.
- Cobertura adicionada para o mapeamento de overrides e para o loader de
  certificados; a suíte completa passou com 558 testes e 1 teste de UI pulado.

## Operação e limite

Instale os `SUFFICIT_SECRET_*` em todas as réplicas antes de remover os valores
legados de `appsettings.*.json`. O `VaultBackedSecretStore` continua reservado
à resolução em runtime: ele não pode ser usado para o primeiro segredo de
conexão, pois o banco é pré-requisito do próprio store.
