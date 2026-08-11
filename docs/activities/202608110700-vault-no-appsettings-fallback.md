# Vault — remoção do fallback de segredos em appsettings

**Data:** 2026-08-11  
**Plano:** [`PLAN-VAULT.md`](../plans/PLAN-VAULT.md)  
**Status:** concluído

## Entregue

- `EnvironmentSecretStore` agora lê somente variáveis `SUFFICIT_SECRET_*`.
- O host valida a configuração antes dos overrides e falha fechado quando uma
  chave de startup conhecida contém valor plaintext em appsettings ou User
  Secrets.
- O caminho opcional de senha de certificado não injeta mais credenciais na
  configuração do processo; a senha de signing/encryption é resolvida pelo
  mesmo `ISecretStore` usado pelos demais consumidores.
- DCR, banco, certificados, provedores externos, SMTP e RabbitMQ usam a
  fronteira de `ISecretStore`; DCR não consulta mais `InitialAccessToken` do
  appsettings como fallback.
- O template de appsettings mantém somente chaves vazias e instruções; os
  valores reais ficam em `/etc/sufficit/identity/vault-secrets.env`.

## Evidência operacional

Os três hosts (`eveo-apps`, `apoint-apps` e `castrum-apps`) foram auditados sem
expor valores: cada arquivo `vault-secrets.env` existe com as chaves usadas,
valores não vazios e permissões `root:www-data:0640`; os
`appsettings.Production.json` ativos têm apenas placeholders vazios para os
segredos de configuração.

Após esta mudança, qualquer reintrodução de uma credencial em appsettings
interrompe o startup com uma mensagem que identifica somente a chave de
configuração, nunca o valor.
