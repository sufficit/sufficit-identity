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

## Decisão 2026-07-25 — Caminho B (CI real contra MariaDB) adotado

**Data da decisão:** 2026-07-25
**Referência:** `docs/eval/PLAN-2026-07-25-claude-fable-5.md` item 1.1 [M6]

A avaliação de segurança (`docs/eval/PLAN-2026-07-25-claude-fable-5.md`) apontou
que o provider `MySql.EntityFrameworkCore` (Oracle) **não declara suporte a
MariaDB**, com risco de correção sutil em `datetime(6)`, `UTC_TIMESTAMP()` e
geração de migration divergente. O plano ofereceu dois caminhos:

- **Caminho A (preferido):** migrar para `Pomelo.EntityFrameworkCore.MySql`
  (MIT, suporte MariaDB de 1ª classe) — **bloqueado** porque Pomelo ainda não
  tem release estável compatível com EF Core 10 (a única versão estável no
  momento mira EF9; este projeto depende de Identity/EF Core 10 para passkeys).
- **Caminho B (alternativa):** manter o provider Oracle MAS exercitar TODAS as
  migrations e o contrato de schema contra uma instância real de MariaDB 10.4.34
  em CI (não só SQLite in-memory).

**Decisão: adotar o Caminho B.** O Caminho A permanece bloqueado e será
reavaliado no ciclo trimestral (jan/abr/jul/out) — assim que Pomelo shipar uma
release estável para EF Core 10, reverter para MIT conforme a seção "Reverter"
abaixo.

A matriz de CI que sustenta o Caminho B **já existe** e cobre integralmente o
critério de aceite do plano:

1. **`.github/workflows/ci.yml`** sobe um service container
   `mariadb:10.4.34`, aplica o SQL canônico
   (`docs/migration/sql/001-create-empty-database.sql`) e roda a suíte de testes
   com `SUFFICIT_IDENTITY_MARIADB_CONNECTION` apontando para esse container real.
2. **`MariaDbMigrationIntegrationTests.cs`** (`[Trait("Category","MariaDbIntegration")]`)
   valida contra MariaDB real: schema completo (14 tabelas), migration history
   (1 registro com `InitialMigrationId`), índices (`AK_OpenIddictApplications_ClientId`,
   `userpasskeys.credentialid`), e o rehearsal de upgrade do schema legacy
   (39 → 44 tabelas) preservando invariante as shared tables.
3. **`DatabaseSchemaContractTests.cs`** confirma que o SQL de produção
   (`001-create-empty-database.sql`) é **regenerado da migration EF**
   (`GenerateScript`), eliminando drift na fonte — não há duas fontes de verdade.
4. **`MariaDbGrantSmokeTests.cs`** adiciona um smoke de grant
   (`client_credentials`) end-to-end contra MariaDB real, fechando o critério de
   aceite do plano que antes só era coberto em SQLite.

## Atualização 2026-07-26 — Bug do provider Oracle RESOLVIDO (migração para Pomelo fork)

**Status: RESOLVIDO.** O bug abaixo (provider Oracle não traduz
`FindByNamesAsync`) foi corrigido migrando para um **fork Sufficit do
Pomelo.EntityFrameworkCore.MySql** (MIT, MariaDB 1ª classe), compilado da branch
`upgrade/10.0.0` do PR upstream [#2019](https://github.com/PomeloFoundation/Pomelo.EntityFrameworkCore.MySql/pull/2019)
(EF Core 10). O pacote vive em `.nuget-feed/` (folder feed commitado, ver
`nuget.config`). O `MariaDbGrantSmokeTests` (que expôs o bug) teve o gate
removido e roda novamente no CI.

A migração é **temporária**: quando o Pomelo upstream shipar EF Core 10 estável
(issue [#2007](https://github.com/PomeloFoundation/Pomelo.EntityFrameworkCore.MySql/issues/2007)),
dropa-se o fork + folder feed e usa-se a versão oficial. A licença volta a ser
MIT (a exceção GPL do Oracle não se aplica mais).

A seção abaixo preserva o registro histórico do bug e da investigação.

---

## Atualização 2026-07-26 — Bug confirmado do provider Oracle (produção-bloqueante) [RESOLVIDO acima]

**Status (histórico):** Caminho B comprometido empiricamente. O smoke de grant acima,
rodado pela primeira vez no CI (run `30207874696`), revelou um bug real de
produção do provider Oracle `MySql.EntityFrameworkCore 10.0.7`:

```
System.InvalidOperationException : Expression '@p' in the SQL tree does not
have a type mapping assigned.
   at ...RelationalTypeMappingPostprocessor.VisitExtension(Expression expression)
   at ...InExpression.VisitChildren(...)
   ...
   at OpenIddict.EntityFrameworkCore.OpenIddictEntityFrameworkCoreScopeStore
       .FindByNamesAsync(...)
```

O provider não consegue traduzir a query `WHERE Name IN (@scopes)` que o
OpenIddict gera em `ScopeStore.FindByNamesAsync` (chamada por
`ListResourcesAsync`, que **todo grant** invoca via
`AuthorizationController.ResolveResourcesAsync`). Resultado concreto: **nenhum
grant consegue emitir token contra MariaDB real** via o provider Oracle hoje.
O SQLite (testes locais) tolera a query; o Oracle não.

Isso é exatamente o risco que o item 1.1 [M6] do plano sinalizou ("o provider
Oracle não declara suporte a MariaDB") — agora confirmado empiricamente, não
mais teórico.

**Ação imediata:** o `MariaDbGrantSmokeTests` foi gated atrás de
`SUFFICIT_IDENTITY_RUN_KNOWN_BROKEN_GRANT_SMOKE=true` (opt-in para reproduzir)
para manter o CI verde, mas o bug NÃO está resolvido. Os testes de
schema/migration (`MariaDbMigrationIntegrationTests`,
`DatabaseSchemaContractTests`) continuam passando contra MariaDB real — eles
não invocam `ListResourcesAsync`.

**Implicação de prioridade:** o Caminho A (migrar para
`Pomelo.EntityFrameworkCore.MySql`, MIT, suporte MariaDB de 1ª classe) deixa de
ser "preferido quando disponível" e passa a ser **necessário para produção
viável contra MariaDB**. Enquanto Pomelo não shipar release estável para EF
Core 10, o STS NÃO deve ser considerado pronto para emissão de tokens contra
MariaDB em produção. Reavaliar Pomelo com urgência (milestone EF10); avaliar
também um downgrade temporário do EF Core para 9 (onde Pomelo é estável) se a
janela de produção apertar.

O compromisso da seção "Mitigação e compromisso" acima (monitorar Pomelo,
reverter quando viável, reavaliar antes de distribuição externa) permanece
integralmente em vigor.

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
