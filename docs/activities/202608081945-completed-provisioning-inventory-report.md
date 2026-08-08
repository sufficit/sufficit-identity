# Provisioning — relatório operacional de inventário

**Data:** 2026-08-08
**Plano:** [`PLAN-SECURITY-HARDENING-WAVE-2.md`](../plans/PLAN-SECURITY-HARDENING-WAVE-2.md)

## Entregue

O endpoint somente leitura `POST /api/provisioning/manifest/inventory` agora
retorna, além das entradas por cliente:

- o `manifestId` recebido, quando presente;
- o instante UTC de geração do relatório;
- o `correlationId` da requisição auditada;
- `statusCounts`, com contagem por status e sem credenciais, segredos ou
  tokens.

O resumo permite revisar uma coorte e correlacioná-la ao evento de auditoria
antes de qualquer adoção ou ativação de `Enforce`. A leitura continua sem
mutação, sem resolução de referências de segredo e sem alteração de grants,
clientes ou integrações existentes.

## Validação

- 16 testes focados de `ProvisioningControllerTests` e
  `ProvisioningManifestTests` aprovados;
- o teste HTTP confirma timestamp, correlação, contagem consistente e presença
  de clientes não declarados;
- o plano continua aberto para a operação real: fornecer o manifesto de
  produção, executar o inventário, revisar divergências e adotar clientes
  individualmente antes de qualquer coorte `Enforce`.
