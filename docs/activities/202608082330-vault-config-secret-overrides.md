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

## Limites desta etapa

- A camada ainda é uma ponte de compatibilidade para o startup; o valor legado
  só deve ser removido depois de instalar os overrides em todas as réplicas.
- A migração dos consumidores para buscar diretamente no `ISecretStore` e a
  ativação de `RequireEncryptionInProduction=true` continuam pendentes.
- Nenhum segredo de produção foi alterado nesta etapa.
