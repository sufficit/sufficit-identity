# Sender constraints — exclusividade DPoP/mTLS

> **Status:** COMPLETED em 2026-08-09. Entrega correspondente ao P0.4 de
> `PLAN-CLAUDE-FABLE-5-REMAINING.md`.

## Entregue

- Uma requisição cuja identidade de emissão carrega binding DPoP e cujo
  certificado mTLS é válido para o mesmo cliente é rejeitada com
  `invalid_request` antes da emissão.
- O erro de protocolo e a descrição são estáveis; não há merge nem
  sobrescrita entre `cnf.jkt` e `cnf.x5t#S256`.
- A seleção de `token_type=DPoP` passou a exigir especificamente um membro
  `jkt`; a mera presença de um `cnf` mTLS não altera o tipo de token.
- A fábrica HTTP de testes ganhou uma ponte exclusiva do TestServer para
  projetar certificado DER em `Connection.ClientCertificate`. Essa ponte não é
  registrada no host de produção.

## Cobertura

- mTLS isolado emite `Bearer` com somente `cnf.x5t#S256`.
- DPoP+mTLS é rejeitado em authorization code, client credentials, refresh
  token e token exchange.
- Refresh token originalmente vinculado a DPoP não pode trocar o mecanismo
  para mTLS.
- Os testes DPoP existentes continuam cobrindo `cnf.jkt`, validação em userinfo
  e rejeição de troca de chave.

## Validação

- `dotnet build Sufficit.Identity.sln -c Release --no-restore`
  - 14 projetos, 0 erros, 0 warnings.
- `dotnet test src/tests/Sufficit.Identity.Tests.csproj -c Release --no-restore`
  - 575 testes aprovados, 1 skip esperado, 0 warnings.
