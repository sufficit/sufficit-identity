# Vault — reemissão do PFX com validade de 10 anos

**Data:** 2026-08-10 23:15 (America/Sao_Paulo)  
**Validade:** 11/08/2026 até 11/08/2036  
**Release reiniciado:** `1d0fb57`

## Entregue

- Reemitido o certificado PFX dedicado do Vault com validade de dez anos.
- A mesma chave RSA-4096 foi preservada intencionalmente: isso permite que as
  chaves do Data Protection e os DEKs já gravados continuem descriptografáveis
  sem regravar o key-ring ou executar migração de ciphertext.
- O novo PFX foi instalado nos três nós em
  `/etc/sufficit/identity/vault-kek.pfx`, com `root:www-data:0640`.
- O PFX anterior foi preservado em
  `/etc/sufficit/identity/vault-kek.previous.pfx` nos três nós para rollback
  operacional durante a janela de observação. O segredo de senha permaneceu
  separado no `vault-secrets.env`.

## Validação

- Reinício canário no eveo concluído com sucesso antes do rollout uniforme.
- Reinício coordenado nos três nós concluído pelo lease de cluster.
- Vault readiness confirmou `Vault KEK dataprotection passed the startup
  readiness probe` em cada réplica.
- Novo PFX apresentou RSA-4096, validade até 2036 e o mesmo hash de chave
  pública entre todas as réplicas.
- `/health` e `/health/ready` públicos retornaram `Healthy`; revisão, JWKS e
  certificado STS permaneceram uniformes.

## Limite de segurança e limpeza

Esta operação estende a validade do certificado, mas não substitui a chave
privada. Se houver suspeita de comprometimento, a chave deve ser trocada com
uma migração de Data Protection/Vault dedicada, não por esta reemissão. Após a
janela de rollback acordada, remover os arquivos `vault-kek.previous.pfx` dos
três hosts e registrar a limpeza sem expor material privado.
