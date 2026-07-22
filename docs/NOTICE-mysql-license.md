# Aviso de Licença — MySql.EntityFrameworkCore (Oracle)

**Data da decisão:** 2026-07-21
**Status:** Aceito temporariamente, com intenção de reversão futura

## Contexto

O `sufficit-identity` (STS OAuth/OIDC) usa MySQL/MariaDB como backing store.
Historicamente usávamos `Pomelo.EntityFrameworkCore.MySql` (licença **MIT**),
que é a escolha preferida da comunidade .NET open-source.

Em 2026-07-21 migramos para `MySql.EntityFrameworkCore` 10.0.7 (Oracle,
licença **GPLv2 + FOSS Exception**) para usar:

- EF Core 10.0.10 (que o Pomelo ainda não suporta — sem release compatível)
- .NET 10 LTS (`net10.0`; `net9.0` saiu de suporte em 2026-05-12)
- as APIs nativas de passkeys do ASP.NET Core Identity 10

Esta migração **desbloqueia** as APIs de passkeys, mas não declara o fluxo
WebAuthn pronto para produção: a UI, os endpoints de attestation/assertion e a
migration da tabela de credenciais continuam sendo uma entrega separada.

## Princípio do projeto Sufficit

> **Sempre que possível, preferimos pacotes com licenças mais abertas
> (MIT, Apache 2.0, BSD) em vez de licenças restritivas (GPL, GPLv2,
> AGPL, comercial).**

Esta migração é uma **exceção temporária**, motivada por bloqueio técnico.

## Mitigação e compromisso

1. **Monitorar ativamente** o release do Pomelo EF Core 10.
   - Upstream: <https://github.com/PomeloFoundation/Pomelo.EntityFrameworkCore.MySql>
   - Milestone EF Core 10: <https://github.com/PomeloFoundation/Pomelo.EntityFrameworkCore.MySql/milestones>
   - Revisar trimestralmente (jan/abr/jul/out).

2. **Reverter para Pomelo assim que viável.** Quando o Pomelo shipar
   release estável compatível com EF Core 10 (e os irmãos
   `sufficit-base/json/utils/efdata/communication` subirem para net10),
   reverter este commit — voltar a ser MIT.

3. **GPLv2 + FOSS Exception é aceitável no contexto atual** porque:
   - O STS é software interno do Sufficit, não distribuído a terceiros
     como produto standalone.
   - FOSS Exception permite combinar com código MIT/Apache sem
     contaminação viral.
   - Não há linkagem estática nem redistribuição do binário MySQL.

4. **Antes de qualquer distribuição externa** (open-sourcing do STS,
   OEM, ISV, white-label), **reavaliar a licença** — pode ser necessário
   voltar para Pomelo ou comprar licença comercial Oracle.

## Mudanças técnicas que esta migração acarretou

- `UseMySql(connStr, ServerVersion.AutoDetect(connStr))` → `UseMySQL(connStr)`
- Driver ADO.NET: `MySqlConnector` → `MySql.Data` (Connector/NET)
- Sem mudanças em `AppDbContext` (UTC_TIMESTAMP, timestamp, snake_case
  são server-side / helpers custom — sobrevivem ao swap)
- Projetos STS, Core, Server, Management, Tests e UI passaram a `net10.0`
- A publicação em `Q-EMAIL` passou a usar `RabbitMQ.Client` diretamente, para
  não reintroduzir Pomelo/EF9 pelo grafo transitivo de `Sufficit.Communication`

## Reverter

```bash
# Em ServiceCollectionExtensions.cs:
db.UseMySQL(connectionString);
# →
db.UseMySql(connectionString, ServerVersion.AutoDetect(connectionString));

# Em Directory.Packages.props:
<PackageVersion Include="MySql.EntityFrameworkCore" Version="10.0.7" />
# →
<PackageVersion Include="Pomelo.EntityFrameworkCore.MySql" Version="<future-ef10-version>" />

# Em src/core/Sufficit.Identity.Core.csproj:
<PackageReference Include="MySql.EntityFrameworkCore" />
# →
<PackageReference Include="Pomelo.EntityFrameworkCore.MySql" />
```

## Referências

- [MySql.EntityFrameworkCore no NuGet](https://www.nuget.org/packages/MySql.EntityFrameworkCore)
- [Licença GPLv2 + FOSS Exception (Oracle)](https://github.com/mysql/mysql-connector-net/blob/9.x/LICENSE)
- [Pomelo issue #1639 — guidance para mover entre providers](https://github.com/PomeloFoundation/Pomelo.EntityFrameworkCore.MySql/issues/1639)
- [FOSS Exception FAQ (Oracle)](https://www.mysql.com/about/legal/licensing/foss-exception/)
