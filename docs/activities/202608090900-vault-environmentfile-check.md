# Vault — ingress seguro por EnvironmentFile

**Data:** 2026-08-09 09:00
**Plano:** [`PLAN-VAULT.md`](../plans/PLAN-VAULT.md)

## Entregue

- O instalador cria `vault-secrets.env` somente quando o arquivo do host ainda
  não existe e preserva valores operacionais em upgrades.
- Os units principal e local carregam o arquivo como `EnvironmentFile` opcional,
  antes do startup do Identity.
- O template versionado contém apenas os nomes permitidos de
  `SUFFICIT_SECRET_*`, sem credenciais.
- `helpers/check-vault-secrets.sh` valida existência, permissões quando
  executado como root, nomes autorizados e valores não vazios sem imprimir
  segredos.
- A cobertura automatizada exercita o caminho válido e rejeita chaves não
  suportadas sem expor o valor de teste.

## Operação e limite

O arquivo preenchido deve ser criado pelo secret manager em cada réplica, com
owner `root:www-data` e modo `0640`. Esta etapa não provisiona nem altera
segredos de produção; após o provisionamento, valide cada host e reinicie
somente a instância correspondente.
