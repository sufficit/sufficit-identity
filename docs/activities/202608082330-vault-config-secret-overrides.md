# Vault — overrides de segredos de configuração

**Data:** 2026-08-08 23:30
**Plano:** [`PLAN-VAULT.md`](../plans/PLAN-VAULT.md)

## Entregue

- O host aplica overrides `SUFFICIT_SECRET_*` antes do bind das opções de
  startup.
- Banco, senhas dos certificados, reCAPTCHA/Turnstile e credenciais dos
  provedores Google, GitHub e Facebook podem sair do `appsettings.*.json` sem
  alterar os consumidores existentes.
- O fallback de configuração foi removido após a migração das réplicas; o
  startup agora rejeita qualquer segredo plaintext encontrado em appsettings.
- O mapeamento e a precedência ambiente > JSON têm cobertura automatizada.
- O runbook documenta os nomes das variáveis e a sequência de migração.

## Atualização — migração dos consumidores (2026-08-09)

- `Program.cs` e `AddSufficitIdentitySTS` agora recebem um `ISecretStore` de
  startup e resolvem por nome lógico a conexão do banco, senhas de certificados
  e credenciais dos provedores externos.
- A ponte de configuração continua disponível somente como fallback de
  compatibilidade durante o rolling deploy; nenhum valor é registrado.
- A cobertura valida o mapeamento completo e a passagem pelo boundary (`VaultTests`
  e `CertificateRotationTests`).

## Limites remanescentes

- A ativação de `RequireEncryptionInProduction=true` permanece uma política de
  rollout independente desta migração de segredos.
- O arquivo `vault-secrets.env` continua sendo instalado e rotacionado pelo
  supervisor do host; o repositório valida somente nomes, presença e permissões.
