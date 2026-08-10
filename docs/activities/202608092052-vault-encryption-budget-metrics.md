# Métrica e orçamento de mensagens AES-GCM do vault

> **Status:** COMPLETED em 2026-08-09. Entrega correspondente ao item P2.2 de
> plano de limites criptográficos do vault.

## Resultado

- Cada criptografia AES-GCM bem-sucedida incrementa
  `sufficit.vault.aes_gcm.encryptions`, particionada por `key.name` e
  `key.version`, sem plaintext, ciphertext, AAD ou identidade de usuário.
- `AesGcmMessageBudgetPerKeyVersion` define um orçamento operacional explícito.
  O default de 250 milhões de mensagens mantém a probabilidade aproximada de
  colisão de nonces aleatórios de 96 bits abaixo de 4e-13.
- Contadores locais emitem warning a 80% e critical ao atingir o orçamento. O
  backend de métricas deve agregar todas as réplicas e reinícios; o contador
  local é apenas um sinal antecipado.
- A rotação automática por volume permanece intencionalmente desligada até que
  a métrica forneça volume e sazonalidade reais. A ação segura atual é alertar,
  confirmar a contagem agregada e executar `RotateKeyAsync` por key name.
- Startup rejeita orçamento fora de 1..2^32, preservando também o limite máximo
  de invocações para nonces aleatórios por versão.

## Validação

- Testes focados de vault/DPoP/telemetria: 56 aprovados, 0 warnings.
- O teste do instrumento confirma as tags exatas e a ausência de campos de
  segredo.
