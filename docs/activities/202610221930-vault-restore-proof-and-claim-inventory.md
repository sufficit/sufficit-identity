# Prova de restauração do cofre (C1) e inventário de claims (B2)

**22/10/2026.** Registro operacional do deployment fora deste repositório; aqui
fica só o que é do produto.

## C1 — o backup restaura e decifra

- `--verify-vault` (`56282e5`) aponta o host para uma cópia do banco e decifra
  todo valor protegido com a autoridade de chave do próprio host; imprime
  contagens e ids que falharam, nunca valores; sai com 1 se algo falhar.
  Segredos do segundo fator em texto claro (backup anterior ao C3) contam como
  falha.
- Para repetir: usuário `SELECT` temporário na cópia restaurada, connection
  string da cópia no ambiente de uma unit oneshot igual à do serviço, e
  `dotnet Sufficit.Identity.Server.dll --contentRoot <raiz da instalação> --verify-vault`.
- A KEK (`vault-kek.pfx`) precisa existir fora do cluster: sem ela o backup do
  banco não decifra.
- `Sufficit:Vault:SecretMigrationComplete=true` declara a postura sem fallback
  de configuração.

## B2 — inventário das claims

Claims persistidas (`userclaims`) e destino:

| Claim | Escopo exigido | Destino | Sensibilidade |
|-------|----------------|---------|---------------|
| `entitlements` | `directives` (ou `entitlements` e sucessores configurados) | AT + id_token | alta (autorização) |
| `name` | `profile` | AT + id_token | baixa |
| `address` | `address` | AT + id_token | média (PII); no token vai como `urn:identity:claim:address` (texto livre legado), também sob `address` |
| `picture` | `profile` | AT + id_token | baixa |
| `website` | `profile` | AT + id_token | baixa |
| `profile` | `profile` | AT + id_token | baixa |

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
exigem o escopo padrão e as duas de autenticação são explícitas. Consumidores
que precisem delas usam o userinfo, que já filtrava por escopo.

O que ainda cair no ramo sem mapeamento é registrado uma vez por tipo e
processo ("Claim inventory: unmapped claim type …"). Sem nenhum registro, pode
desligar `IncludeUnmappedClaimsInAccessTokens`.

Primeira hora em produção (`37eefbc`): o log apontou `sub`, `oi_scp`,
`oi_rsrc` (protocolo, do OpenIddict — agora explícitos, fora do inventário) e
`urn:identity:claim:address`: o endereço remapeado escapava do escopo e ia
para qualquer access token. Passou a exigir `address`; o teste que esperava o
endereço num token pedido só com `profile` foi corrigido para provar os dois
lados.

## `directive` persistida: eliminada

Havia claims `directive` duplicando exatamente uma `entitlements` do mesmo
usuário, porque um registro de escopo no banco ainda declarava a concessão com
o tipo `directive`. Corrigido o registro, apagadas as duplicatas, e o
provisionador de concessões passa a gravar `directive` como `entitlements`,
nunca uma segunda linha.

## O nome `directive` sai da emissão

Antes da mudança, conferir que cada consumidor lê `entitlements` (pacote
`Sufficit.Identity.Core` ≥ 1.26.0902, ou código próprio que lê os dois nomes).
Agora tokens, introspecção e userinfo levam a concessão só como
`entitlements`; um valor ainda guardado como `directive` é renomeado na saída
(`NormalizeEntitlementClaimName`), e contas de serviço deixam de receber a
cópia. O mapeamento `directive` → `directives` continua para esse caso.
