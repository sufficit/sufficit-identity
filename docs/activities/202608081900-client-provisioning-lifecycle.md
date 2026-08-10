# Client provisioning lifecycle — transições, Observe e inventário

**Data:** 2026-08-08
**Commits:** `162634a`, `62819f7`
**Plano:** [`PLAN-SECURITY-HARDENING-WAVE-2.md`](../plans/PLAN-SECURITY-HARDENING-WAVE-2.md)

## Entregue

- A validação compartilhada de definição de cliente compara o estado atual com
  o desejado e exige autorização explícita para conversão
  confidential→public, remoção de segredo, substituição de redirect URI e
  expansão para escopos reservados.
- A autorização de transição exige identidade do operador e fica registrada no
  fluxo de provisioning; nenhuma credencial é escrita no audit log.
- Manifests suportam `Observe` e `Enforce`. O modo `Observe` produz uma mudança
  `Observed`, registra a decisão e não altera o cliente existente.
- O provisioning continua exigindo `adoptExisting=true` para assumir clientes
  sem marcador ou pertencentes a outro manifesto; a adoção é auditada.
- `POST /api/provisioning/manifest/inventory` fornece uma leitura sem mutação
  com os estados `DeclaredMissing`, `DeclaredCurrent`, `DeclaredDrifted`,
  `DeclaredUnmanaged`, `DeclaredOwnedByAnotherManifest`,
  `ManagedButUndeclared` e `UnmanagedAndUndeclared`.
- O inventário não resolve referências de segredo e usa a capability de
  preview, com auditoria PII-free.
- `Enforce` agora exige `manifestId` estável; manifests legados continuam
  válidos em `Observe`, preservando a implantação gradual.

## Compatibilidade

O padrão do manifest continua sendo `Observe`; grants, endpoints, tipos de
cliente e integrações existentes não foram removidos. A aplicação de mudanças
sensíveis só ocorre quando o operador seleciona `Enforce` e autoriza a
transição correspondente.

## Validação

- 12 testes focados de provisioning passaram com a pré-condição de identidade.
- 511 testes do backend passaram com o inventário incluído.
- Builds de Management e STS passaram sem warnings.
- CI `31269725265` passou build, SQL MariaDB, testes, smoke API, auditoria de
  vulnerabilidades e gitleaks.

## Pendências operacionais

- O repositório não contém o manifest real de produção; somente o exemplo de
  migração. O operador deve fornecer o manifest versionado da implantação.
- Executar o inventário em produção, revisar divergências e adotar clientes
  individualmente antes de qualquer coorte `Enforce`.
- Registrar a aprovação e a janela de rollback de cada coorte; não executar
  adoção automática nem remover o caminho de compatibilidade durante a
  migração.
