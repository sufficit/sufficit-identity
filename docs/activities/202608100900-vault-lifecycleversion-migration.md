# Migração da coluna `vaultkeys.lifecycleversion`

**Data:** 10/08/2026  
**Status:** Concluída

## Contexto

O worker de métricas registrava `Unknown column 'v.lifecycleversion' in 'field list'` ao consultar a tabela `vaultkeys`. O erro afetava somente a exportação de métricas; não era a causa dos erros HTTP 500 da Management UI.

## Causa

A migração `20260809224037_AddVaultSigningKeyLifecycle` já existia no código e no pacote SQL, mas a unidade `sufficit-identity-migrator.service` não carregava `/etc/sufficit/identity/vault-secrets.env`. Sem a senha do certificado dedicado do Vault, o processo migrador abortava durante a inicialização, antes de adquirir o lock e aplicar as migrações pendentes.

## Correção

- A unidade do migrador passou a carregar o mesmo arquivo de segredos usado pelo serviço principal.
- A migração foi executada em modo idempotente pelo serviço dedicado, sem reiniciar o serviço Identity.
- A coluna `lifecycleversion` e os demais campos da migração de ciclo de vida foram verificados no schema.
- Foi adicionada uma asserção de deployment para impedir regressão da configuração da unidade.

Nenhum valor secreto é registrado nesta atividade ou nos logs de validação.

## Operação

Para aplicar futuras migrações:

```bash
sudo systemctl daemon-reload
sudo systemctl reset-failed sufficit-identity-migrator.service
sudo systemctl start sufficit-identity-migrator.service
sudo systemctl status sufficit-identity-migrator.service --no-pager -l
```

O serviço usa lock distribuído no banco (`sufficit_identity_schema_migrator`), portanto somente uma instância aplica a migração por vez.
