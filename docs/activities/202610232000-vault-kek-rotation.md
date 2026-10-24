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

## Ensaio em produção (23/10)

Deploy nos três nós e `--rewrap-vault-kek` no eveo sem KEK anterior
configurada (`kek-rehearsal-20261023`): key-ring do Data Protection 1 chave já
sob a KEK ativa; `vaultkeys` 3 linhas já sob a KEK ativa e **2 que nenhuma KEK
abre**: `identity-metrics-export:1` e `personal-secrets:1`. As duas têm 132
bytes com o cabeçalho `09F0C9F0` do Data Protection — embrulhadas em agosto,
quando `KeySource` era `dataprotection`, e nunca migradas; o key-ring daquela
época já expirou. Nenhum dado as usa (a configuração de métricas está na
versão 2; nenhuma coluna cifrada aponta para `personal-secrets`, e o código não
usa mais esse nome). O `--verify-vault` não as via porque só confere segredos
nomeados e segundo fator. Saída 1, journal não gravado, auditoria com
`failed`.

## Limpeza das duas chaves órfãs (24/10)

Com o aval do titular, as duas linhas foram apagadas (`vaultkeys` id 3 e 6, com
guarda de tamanho, cabeçalho e versão); cópia em
`/root/vaultkeys-orphans-dataprotection-20261024.tsv` no `eveo-apps` (0600).
Nova recifragem (`kek-rehearsal-20261024`): 3 chaves e 1 chave do key-ring já
sob a KEK ativa, 0 falhas, código 0, journal gravado. `--verify-vault`: 86
segredos nomeados e 71 segredos de segundo fator decifrados, 0 falhas.
