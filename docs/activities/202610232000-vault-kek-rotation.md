# Rotação da KEK do Vault (C1, 23/10/2026)

Até aqui dava para rotacionar chaves de dados (`RotateKeyAsync`) e chaves de
assinatura, mas não a KEK: trocar `vault-kek.pfx` deixava toda chave embrulhada
antes sem quem a abrisse, e o key-ring do Data Protection junto.

## O que entrou

- `Sufficit:Vault:PreviousCertificatePaths`: KEKs em aposentadoria, só para
  decifrar, abertas com a senha da KEK ativa. Valem para as chaves de dados
  (`CertificateKeySource` tenta a ativa e depois as anteriores) e para o
  key-ring do Data Protection (`UnprotectKeysWithAnyCertificate`).
- `--rewrap-vault-kek --operation-id=<id> --reason=<texto>`, em um nó:
  - recifra sob a KEK ativa cada linha de `vaultkeys` que ela ainda não
    protege, uma chave por vez sob o lease da própria chave (o mesmo da
    criação e rotação de chaves, então não corre com outra réplica), e
    invalida o snapshot dela;
  - recifra o key-ring do Data Protection (`DataProtectionKeyRingRewrap`), que
    o Data Protection nunca recifra sozinho;
  - confere que a KEK ativa sozinha abre todas as linhas;
  - grava o journal (`vaultsigningkeyoperations`, ação `kek_rewrap`) só quando
    nada falhou, e um evento de auditoria permanente (`vault.kek.rewrap`);
  - é idempotente: linhas já sob a KEK ativa são puladas e um
    `--operation-id` concluído não refaz nada.
- Advisory `vault-kek-previous-configured` enquanto houver KEK anterior
  configurada.
- Procedimento em `RUNBOOK-VAULT.md`, "Rotação da KEK (troca de chave)":
  fase de leitura com a nova como anterior, troca, recifragem, verificação,
  janela de rollback, remoção.

## Testes (`VaultTests.KekRewrap.cs`)

- KEK anterior só decifra; a ativa sozinha embrulha.
- Recifragem com duas versões de uma chave e outra chave: depois dela, só a
  KEK nova decifra o que a antiga escreveu (inclusive a versão 1); repetir é
  inócuo.
- Chave que nenhuma KEK configurada abre (perda): aparece em `Failed` e o
  journal não é gravado.
- Key-ring do Data Protection recifrado: um payload protegido sob a KEK antiga
  abre com um provedor que só conhece a nova.
- Advisory de postura.

A restauração a partir de backup já tinha prova (`--verify-vault`,
[`202610221930`](202610221930-vault-restore-proof-and-claim-inventory.md)).
Fica no plano um teste de recifragem concorrendo com uma rotação de chave de
dados em outra réplica.

## Limpeza

O `vault-kek.previous.pfx` saiu dos três nós: tinha a mesma chave pública do
`vault-kek.pfx` (reemissão de agosto que só estendeu a validade) e nada o
referenciava.
