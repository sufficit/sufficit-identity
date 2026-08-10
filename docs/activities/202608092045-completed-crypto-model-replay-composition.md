# Modelo criptográfico e composição de replay

> **Status:** COMPLETED em 2026-08-09. Entrega dos itens P2 de limpeza do
> envelope criptográfico, composição DPoP e reavaliação de enums em
> `PLAN-CLAUDE-FABLE-5-REMAINING.md`.

## Resultado

- `EnvelopeCrypto` ficou restrito à criptografia de dados AES-256-GCM. Os
  métodos mortos `Wrap/Unwrap` e o teste que sugeria uma KEK AES foram
  removidos.
- Entidade, formato autocontido e `PLAN-VAULT` agora descrevem corretamente o
  wrapped key como blob opaco do `IVaultKeyEncryptionKeySource`: RSA-OAEP, Data
  Protection ou KMS/HSM externo, conforme o backend.
- A camada `IDistributedCache` de replay DPoP passou a se declarar apenas uma
  otimização não atômica. `RollingDpopReplayCache` exige por tipo uma
  `IAtomicDpopReplayCache`, implementada pela tabela com chave única no banco.
- Um teste de composição prova que a primeira aceitação no cache sempre chega à
  autoridade atômica; isso impede remover silenciosamente a proteção de banco.

## Decisão sobre modos de enforcement

Os enums não foram fundidos. `Observe`, `Audit`, `ReportOnly` e os modos de
topologia/revogação têm semânticas e contratos de configuração diferentes; uma
migração de nomes quebraria binding e não reduziria decisões de segurança. O
contrato comum já existe em `IProductionPostureContributor`, que converte cada
modo permissivo em finding e acknowledgement estruturado. Portanto não há
benefício mensurável em uma migração de tipos nesta etapa.

## Validação

- Testes focados de vault e DPoP: 55 aprovados, 0 warnings.
