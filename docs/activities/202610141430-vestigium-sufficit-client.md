# Client `vestigium-sufficit` (client_credentials) — cadastro direto

Data: 2026-10-14. Pedido do dono: autenticação definitiva e genérica do Vestigium no endpoints.

## Motivo

O tenant `sufficit` do Vestigium usava um handle de reference token do Identity antigo (Duende),
invalidado na migração para OpenIddict; o viewer recebia 401. Token pessoal novo dura no máximo
90 dias e depende de uma pessoa. Cada tenant do Vestigium passa a ter o próprio client confidencial.

## O que foi feito

INSERT direto em `identity.applications` (a API de gestão exige login de gestão interativo, sem
device flow; a concessão em `identity:client:entitlements` é, por desenho, mantida no banco):

- `client_id = vestigium-sufficit`, `client_type = confidential`, `consent_type = implicit`,
  `display_name = Vestigium - tenant sufficit`;
- `permissions = ["ept:token", "gt:client_credentials", "scp:entitlements"]`;
- `properties = {"identity:client:entitlements": ["telephonyclient:00000000-0000-0000-0000-000000000000"]}`
  (concessão global: o tenant da Sufficit visualiza o plano de qualquer cliente);
- `client_secret`: hash OpenIddict (PBKDF2-HMAC-SHA256, 10.000 iterações, salt de 128 bytes),
  mesmo formato dos clients existentes. Sem linha em `oauthclientcredentials` (segredo primário).

Validação: `POST /connect/token` com `client_credentials` + `scope=entitlements` emitiu token de
3600 s; o endpoints autenticou o token (403 antes da política nova, em vez de 401).

## Onde está o segredo

Somente em `vestigium.vest_tenantendpoint.AuthConfig` do tenant `sufficit` (consumidor). A cópia no
Vault do Identity ficou pendente: o MCP do Identity estava sem autorização na sessão.

## Reverter / rotacionar

- Revogar: `DELETE FROM applications WHERE client_id='vestigium-sufficit'` (ou rotacionar pelo
  `POST /api/clients/vestigium-sufficit/secret/rotate` e atualizar o `AuthConfig` do tenant).
- Restringir a clientes específicos: trocar o contexto vazio por `telephonyclient:<contextid>`.

Relacionados: sufficit-endpoints PR #42 (`VestigiumDialPlanAuthorization`), sufficit-vestigium
`c6c0494` (tipo `oauth2-client-credentials`).
