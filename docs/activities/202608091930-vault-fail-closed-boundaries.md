# Vault — boundaries fail-closed de produção

> **Status:** COMPLETED em 2026-08-09. Entrega de código correspondente ao
> P0.5 do plano de vault; a migração dos ambientes continua
> como gate operacional no plano.

## Entregue

- `RequireEncryptionInProduction` inicia em `true` e permanece no binding
  apenas por compatibilidade. Defini-lo como `false` não desliga mais o guard.
- `PassThroughKeyVault` só pode ser registrado em Development. Fora desse
  ambiente, `Enabled=false` encerra o startup com erro.
- O template de servidor inicia com vault e requirement habilitados.
- O fallback de referência plaintext para client secrets exige a capability
  explícita do backend pass-through. Com `KeyVault` real, formato inválido lança
  `ClientSecretResolutionException` e não retorna a referência como segredo.
- O hash AAD valida tamanho e usa
  `CryptographicOperations.FixedTimeEquals`; AES-GCM continua autenticando o AAD
  completo e o ciphertext.
- O runbook foi atualizado para exigir configuração cifrada antes da
  implantação, canário, telemetria de leitura `pt1.`, rewrite e rollback
  limitado.

## Cobertura

- startup não-Development rejeita vault desabilitado mesmo com o booleano
  legado falso;
- Development mantém o backend pass-through para testes e desenvolvimento;
- `pt1.` continua legível pelo vault real durante a migração e novas escritas
  produzem `v1.`;
- plaintext cru não resolve com vault real;
- AAD incorreto, hash AAD de tamanho diferente, ciphertext truncado e tampering
  falham fechados.

## Validação

- `VaultTests`: 29 testes aprovados, 0 warnings.
- Suíte sem o contrato documental interferido por arquivo Strix externo:
  578 testes aprovados, 0 warnings.
- A suíte integral chegou a 578 aprovados e uma falha alheia à entrega:
  `docs/security/strix-identity-scope.md`, arquivo não versionado criado em
  paralelo, viola a convenção de prefixos. O arquivo foi preservado.

## Gate ainda aberto

- Cada ambiente precisa comprovar inventário, rewrite de todos os valores
  `pt1.`, zero leituras legadas durante a janela definida e rollback testado.
  Nenhuma dessas evidências é inferida a partir dos testes locais.
