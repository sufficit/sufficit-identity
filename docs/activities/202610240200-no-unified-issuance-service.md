# Decisão: sem serviço único de emissão (B1, 24/10/2026)

Pergunta do plano: vale um `ITokenIssuanceService` que cubra as duas fronteiras
de emissão?

1. **Grants OAuth** (código, refresh, client credentials, troca de token,
   CIBA, device, assertion): pipeline do OpenIddict, access token JWT, id token
   e às vezes refresh token. Ponto único: `TokenGrantDispatcher` +
   `GrantOperations` (`BuildIdentityAsync`, `GetDestinations`,
   `ResolveResourcesAsync`, `ApplyDpopBinding`, `SignIn`).
2. **Emissão privilegiada** (operator, provisionamento, pessoal): despacha
   `GenerateTokenContext` direto para um token de referência. Ponto único:
   `ApplyScaffoldingAsync`.

**Resposta: não.** A duplicação que o item supunha foi removida em setembro
([`202609201400`](202609201400-one-issuance-boundary.md)). Um contrato para os
dois seria a união de dois formatos — vários tokens com sessão de login × um
token de referência sem login — e só acrescentaria opções que valem para um
lado. As regras críticas (destinos, recursos, DPoP, registro de emissão) já
estão centralizadas dentro de cada fronteira.

Consequência para o plano: o B2 (`IClaimReleasePolicy`) é uma política usada
pelas duas fronteiras, sem depender do serviço; B3 e B5 são baterias de teste
e seguem independentes.
