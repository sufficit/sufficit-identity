# Vault — overrides de segredos de configuração

**Data:** 2026-08-08 23:30
**Plano:** [`PLAN-VAULT.md`](../plans/PLAN-VAULT.md)

## Entregue

- O host aplica overrides `SUFFICIT_SECRET_*` antes do bind das opções de
  startup.
- Banco, senhas dos certificados, reCAPTCHA/Turnstile e credenciais dos
  provedores Google, GitHub e Facebook podem sair do `appsettings.*.json` sem
  alterar os consumidores existentes.
- O fallback de configuração continua disponível durante o rolling deploy e
  emite aviso com o nome lógico do segredo, sem registrar o valor.
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

- A camada de configuração ainda é uma ponte de compatibilidade para o startup;
  o valor legado só deve ser removido depois de instalar os overrides em todas
  as réplicas.
- A ativação de `RequireEncryptionInProduction=true` e a remoção definitiva dos
  valores JSON são operações de rollout, não mudanças de código desta etapa.
- Nenhum segredo de produção foi alterado nesta etapa.
