# Prova de restauração do cofre (C1) e inventário de claims (B2)

**22/10/2026.**

## C1 — o backup restaura e decifra

- **Backup:** o banco `identity` tem dump diário no Databasement (CT 3175,
  `data-cluster`, retenção 3 dias, cópia no GCS `suff-databasement-us`) e
  restauração semanal no CT 3176 (sábado 09:00).
- **Prova:** `--verify-vault` (novo, `56282e5`) aponta o host para uma cópia
  e decifra todo valor protegido com a autoridade de chave do próprio host;
  imprime contagens e ids que falharam, nunca valores; sai com 1 se algo
  falhar. Rodado no castrum-apps (unit oneshot copiada da do serviço, para
  ter o mesmo ambiente):
  - cópia restaurada de 18/10 no CT 3176: **72/72 segredos nomeados**
    decifrados. O segundo fator saiu 0/71 porque esse backup é anterior ao
    C3 (texto claro conta como falha);
  - produção: **80/80 segredos nomeados, 71/71 segredos do segundo fator**.
  Usuário temporário de leitura no 3176 e unit removidos depois.
- **KEK:** `vault-kek.pfx` idêntico (sha256 `cc30326a…`) nos três nós e na
  cópia local da estação do operador (`sufficit-servers/eveo-apps/etc/sufficit/identity`,
  fora do git); a senha local abre o PFX. Os CTs de app não têm vzdump, então
  fora do cluster a única cópia é a da estação.
- `Sufficit:Vault:SecretMigrationComplete=true` declarado nos três nós
  (backup `appsettings.Production.json.bak-vault-migration-20261022`); postura
  aprovada, sem fallback de configuração.

Para repetir após a próxima restauração semanal (que já terá o segundo fator
cifrado): usuário `SELECT` temporário no 3176 para 172.19.3.101, connection
string da cópia no ambiente da unit, `dotnet Sufficit.Identity.Server.dll
--contentRoot /opt/sufficit-identity --verify-vault`.

## B2 — inventário das claims

Tipos persistidos em produção (`userclaims`; `roleclaims` vazio):

| Claim | Usuários | Escopo exigido | Destino | Sensibilidade | Dono/consumidor |
|-------|---------:|----------------|---------|---------------|-----------------|
| `entitlements` | 1231 | `directives` (ou `entitlements`, `fleet.api`) | AT + id_token | alta (autorização) | consumidores por contexto; já mapeada |
| `directive` | 17 | `directives` | AT + id_token | alta | legado de `entitlements`; já mapeada |
| `name` | 71 | `profile` | AT + id_token | baixa | regra própria |
| `address` | 42 | `address` | AT + id_token | média (PII) | userinfo |
| `picture` | 36 | `profile` | AT + id_token | baixa | userinfo (Run lê dali) |
| `website` | 15 | `profile` | AT + id_token | baixa | — |
| `profile` | 2 | `profile` | AT + id_token | baixa | — |

Acrescentadas na emissão (factory de sessão):

| Claim | Destino | Por quê |
|-------|---------|---------|
| `aal` | só AT | nível de garantia, lido pelas APIs do próprio Identity |
| `identity:mfa_remembered` | só AT | a gestão exige 2º fator novo quando o do bearer é lembrado; tirar faria o lembrado parecer novo |
| `amr`, `acr`, `auth_time` | AT + id_token | já explícitas |
| `sid` | só id_token | já explícita |

Antes, `address`, `picture`, `website`, `profile`, `aal` e
`identity:mfa_remembered` caíam no ramo "sem mapeamento" e iam para o access
token de qualquer cliente, qualquer escopo. Agora as claims-padrão do OIDC
exigem o escopo padrão e as duas de autenticação são explícitas. Nenhum
consumidor em produção lê essas claims do token (o Run usa o userinfo, que já
filtrava por escopo). Clientes interativos sem `profile`: ferramentas
(Swagger, Postman, DCR).

O que ainda cair no ramo sem mapeamento é registrado uma vez por tipo e
processo ("Claim inventory: unmapped claim type …"). Sem nenhum registro, pode
desligar `IncludeUnmappedClaimsInAccessTokens`.
