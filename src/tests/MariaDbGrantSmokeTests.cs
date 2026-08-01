using System.Data.Common;
using System.Net;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Sufficit.Identity.Core.Data;
using Sufficit.Identity.STS;
using Sufficit.Identity.Tests.Infrastructure;
using Xunit;

namespace Sufficit.Identity.Tests;

/// <summary>
/// Smoke de grant end-to-end contra uma instância REAL de MariaDB 10.4.34,
/// fechando o critério de aceite do item 1.1 [M6] de
/// <c>docs/plans/PLAN-LEGACY-CUTOVER.md</c>: a matriz de CI já
/// validava schema/migration contra MariaDB (<see cref="MariaDbMigrationIntegrationTests"/>
/// e <see cref="DatabaseSchemaContractTests"/>), mas nenhum teste exercitava
/// um grant OAuth efetivo no provider MySQL real — eles rodavam só em SQLite
/// in-memory. Este smoke provisiona o banco real (mesmo provider de produção:
/// <c>MySql.EntityFrameworkCore</c>) e roda um fluxo
/// <c>client_credentials</c> completo (token + introspection), provando que o
/// caminho de dados do STS funciona contra MariaDB, não só o DDL.
///
/// <para><b>Gating:</b> respeita as MESMAS variáveis de ambiente de CI que
/// <see cref="MariaDbMigrationIntegrationTests"/> —
/// <c>SUFFICIT_IDENTITY_MARIADB_CONNECTION</c> (connection string) e
/// <c>SUFFICIT_IDENTITY_ALLOW_EPHEMERAL_DATABASE_REHEARSAL</c> (autorização
/// para operações destrutivas numa database efêmera). Em dev local (sem as
/// variáveis) o teste é SKIPADO, não falha — espelha o contrato já firmado
/// pela classe irmã.</para>
/// </summary>
public sealed class MariaDbGrantSmokeTests
{
    // Espelham MariaDbMigrationIntegrationTests.ConnectionEnvironmentVariable/
    // RehearsalEnvironmentVariable (private const lá). Mantidos como literais
    // aqui (e não como referência cruzada) para não acoplar os dois testes num
    // contrato internal; os valores são estables e já documentados no CI.
    private const string ConnectionEnvironmentVariable =
        "SUFFICIT_IDENTITY_MARIADB_CONNECTION";
    private const string RehearsalEnvironmentVariable =
        "SUFFICIT_IDENTITY_ALLOW_EPHEMERAL_DATABASE_REHEARSAL";

    private const string SmokeDatabase = "identity_grant_smoke";

    [Fact]
    [Trait("Category", "MariaDbIntegration")]
    public async Task Client_credentials_grant_works_end_to_end_against_real_mariadb()
    {
        // 2026-07-26: this smoke exposed a production-blocking bug in the Oracle
        // provider (FindByNamesAsync IN(@p) translation failure, CI run
        // 30207874696). That bug is now RESOLVED by migrating to a Sufficit fork
        // of Pomelo.EntityFrameworkCore.MySql (EF Core 10, built from upstream
        // PR #2019). The gate that was added when the bug was Oracle-side is
        // removed: this test now runs in CI against real MariaDB as originally
        // intended. If it fails again, the cause is in this project's code, not
        // the provider.
        var connectionString = Environment.GetEnvironmentVariable(ConnectionEnvironmentVariable);
        if (string.IsNullOrWhiteSpace(connectionString))
        {
            Assert.False(
                string.Equals(Environment.GetEnvironmentVariable("CI"), "true",
                    StringComparison.OrdinalIgnoreCase),
                $"{ConnectionEnvironmentVariable} is required in CI.");
            return;
        }

        if (!string.Equals(
                Environment.GetEnvironmentVariable(RehearsalEnvironmentVariable),
                "true",
                StringComparison.OrdinalIgnoreCase))
        {
            Assert.False(IsContinuousIntegration(),
                $"{RehearsalEnvironmentVariable}=true is required in CI.");
            return;
        }

        var smokeConnectionString = await ProvisionEphemeralDatabaseAsync(connectionString);

        try
        {
            // O factory (abaixo) NÃO chama EnsureCreated: o schema já vem do SQL
            // canônico aplicado em ProvisionEphemeralDatabaseAsync (mesma fonte
            // de verdade que a migration EF gera — ver DatabaseSchemaContractTests).
            // Usar EnsureCreated aqui recriaria as tabelas e divergiria do
            // caminho de produção, que é exatamente o que este smoke quer exercer.
            await using var factory = new MariaDbTestFactory(smokeConnectionString);
            await ((IAsyncLifetime)factory).InitializeAsync();

            var client = factory.CreateClient();

            // client_credentials é o grant mais barato para um smoke que NÃO
            // depende de cookie/login UI (que vive no repo irmão): basta o
            // client confidencial + seu secret. Exercita AppDbContext +
            // OpenIddict application/scope/token stores no provider MySQL real,
            // o caminho de dados que o SQLite dos outros testes nunca toca.
            var (tokenStatus, tokenBody) = await client.PostFormAsync("/connect/token", new Dictionary<string, string>
            {
                ["grant_type"] = "client_credentials",
                ["client_id"] = TestDataSeeder.ClientCredentialsClientId,
                ["client_secret"] = TestDataSeeder.ClientCredentialsClientSecret,
                ["scope"] = TestDataSeeder.ScopeName,
            });

            Assert.Equal(HttpStatusCode.OK, tokenStatus);
            Assert.Equal("Bearer", tokenBody.GetProperty("token_type").GetString());
            var accessToken = tokenBody.GetProperty("access_token").GetString();
            Assert.False(string.IsNullOrEmpty(accessToken));

            // Introspection fecha o ciclo: prova que o access token foi
            // PERSISTIDO no store do OpenIddict contra MariaDB (reference tokens
            // — UseReferenceAccessTokens — só validam via introspecção, que lê
            // o token da tabela `tokens`).
            client.DefaultRequestHeaders.Authorization = IntrospectionTests.BasicAuthFor(
                TestDataSeeder.IntrospectionClientId, TestDataSeeder.IntrospectionClientSecret);

            var (introspectStatus, introspectBody) = await client.PostFormAsync("/connect/introspect", new Dictionary<string, string>
            {
                ["token"] = accessToken!,
            });

            Assert.Equal(HttpStatusCode.OK, introspectStatus);
            Assert.True(introspectBody.GetProperty("active").GetBoolean());
        }
        finally
        {
            await DropEphemeralDatabaseAsync(connectionString);
        }
    }

    /// <summary>
    /// Cria uma database efêmera <see cref="SmokeDatabase"/> ao lado da
    /// <c>identity_contract</c> usada pelos testes de schema, aplica o SQL
    /// canônico (<c>001-create-empty-database.sql</c>) e devolve uma connection
    /// string apontando para ela. Espelha o rehearsal de
    /// <see cref="MariaDbMigrationIntegrationTests"/> — mesma dance restrita a
    /// loopback + mesmo guard de ambiente.
    /// </summary>
    private static async Task<string> ProvisionEphemeralDatabaseAsync(string connectionString)
    {
        var source = new DbConnectionStringBuilder { ConnectionString = connectionString };

        Assert.Contains(
            GetConnectionValue(source, "server"),
            new[] { "127.0.0.1", "localhost", "::1" },
            StringComparer.OrdinalIgnoreCase);

        RemoveConnectionValue(source, "database");

        await using var adminContext = CreateContext(source.ConnectionString);
        await using var adminConnection = adminContext.Database.GetDbConnection();
        await adminConnection.OpenAsync();

        await ExecuteNonQueryAsync(adminConnection, $"DROP DATABASE IF EXISTS `{SmokeDatabase}`");
        await ExecuteNonQueryAsync(adminConnection, $"""
            CREATE DATABASE `{SmokeDatabase}`
                CHARACTER SET utf8mb4
                COLLATE utf8mb4_general_ci
            """);

        source["database"] = SmokeDatabase;
        var smokeConnectionString = source.ConnectionString;

        // Aplica o SQL canônico no banco efêmero (mesmo arquivo que o CI aplica
        // em identity_contract — única fonte de verdade, regenerada da migration
        // EF, ver DatabaseSchemaContractTests).
        await using var dataContext = CreateContext(smokeConnectionString);
        await using var dataConnection = dataContext.Database.GetDbConnection();
        await dataConnection.OpenAsync();

        var scriptPath = ResolveMigrationFile("sql", "001-create-empty-database.sql");
        await ExecuteScriptAsync(dataConnection, scriptPath);

        return smokeConnectionString;
    }

    private static async Task DropEphemeralDatabaseAsync(string connectionString)
    {
        var source = new DbConnectionStringBuilder { ConnectionString = connectionString };
        RemoveConnectionValue(source, "database");

        try
        {
            await using var adminContext = CreateContext(source.ConnectionString);
            await using var adminConnection = adminContext.Database.GetDbConnection();
            await adminConnection.OpenAsync();
            await ExecuteNonQueryAsync(adminConnection, $"DROP DATABASE IF EXISTS `{SmokeDatabase}`");
        }
        catch
        {
            // Best-effort: o CI destroy o container inteiro depois do job de
            // qualquer forma; não deixar um cleanup falho mascarar a falha real
            // do teste (que já foi asserted acima).
        }
    }

    private static AppDbContext CreateContext(string connectionString)
    {
        var options = new DbContextOptionsBuilder<AppDbContext>()
            .UseMySql(
                connectionString,
                new MariaDbServerVersion(
                    new Version(10, 4, 34)),
                mysql => mysql.MigrationsHistoryTable(IdentityDatabaseSchema.MigrationsHistoryTable))
            .Options;
        return new AppDbContext(options);
    }

    private static async Task ExecuteScriptAsync(DbConnection connection, string fileName)
    {
        var script = await File.ReadAllTextAsync(fileName);
        var statements = System.Text.RegularExpressions.Regex
            .Split(script, @"(?m);\s*(?:\r?\n|$)")
            .Select(statement => statement.Trim())
            .Where(statement => statement.Length > 0);
        foreach (var statement in statements)
        {
            await ExecuteNonQueryAsync(connection, statement);
        }
    }

    private static async Task ExecuteNonQueryAsync(DbConnection connection, string commandText)
    {
        await using var command = connection.CreateCommand();
        command.CommandText = commandText;
        await command.ExecuteNonQueryAsync();
    }

    private static string GetConnectionValue(DbConnectionStringBuilder builder, string name)
    {
        var key = builder.Keys.Cast<string>().SingleOrDefault(candidate =>
            string.Equals(candidate.Replace(" ", string.Empty, StringComparison.Ordinal),
                name, StringComparison.OrdinalIgnoreCase));
        return key is null
            ? string.Empty
            : Convert.ToString(builder[key], System.Globalization.CultureInfo.InvariantCulture) ?? string.Empty;
    }

    private static void RemoveConnectionValue(DbConnectionStringBuilder builder, string name)
    {
        var key = builder.Keys.Cast<string>().SingleOrDefault(candidate =>
            string.Equals(candidate.Replace(" ", string.Empty, StringComparison.Ordinal),
                name, StringComparison.OrdinalIgnoreCase));
        if (key is not null)
        {
            builder.Remove(key);
        }
    }

    private static string ResolveMigrationFile(params string[] path)
    {
        var directory = new DirectoryInfo(AppContext.BaseDirectory);
        while (directory is not null &&
               !File.Exists(Path.Combine(directory.FullName, "Sufficit.Identity.sln")))
        {
            directory = directory.Parent;
        }
        if (directory is null)
        {
            throw new DirectoryNotFoundException(
                "Could not locate the Sufficit.Identity repository root.");
        }
        return Path.Combine([directory.FullName, "docs", "migration", .. path]);
    }

    private static bool IsContinuousIntegration() =>
        string.Equals(Environment.GetEnvironmentVariable("CI"), "true",
            StringComparison.OrdinalIgnoreCase);
}

/// <summary>
/// <see cref="WebApplicationFactory{TEntryPoint}"/> isolada que aponta o STS
/// para uma instância MariaDB real (em vez do SQLite in-memory do
/// <see cref="SufficitIdentityTestFactory"/>). Réplica mínima do factory
/// compartilhado, trocando apenas o provider de dados: tudo o mais
/// (configuração, controllers, endpoints) é idêntico, de modo que um smoke
/// verde aqui significa "o STS funciona contra MariaDB", não "uma configuração
/// de teste ad hoc funciona".
/// </summary>
file sealed class MariaDbTestFactory : WebApplicationFactory<MariaDbTestFactory>, IAsyncLifetime
{
    private readonly string _connectionString;

    // xUnit/MySql.Data podem refletir sobre construtores sem parâmetros em
    // alguns caminhos; mantemos um default inofensivo (a connection real é
    // sempre passada pelo teste que instancia este factory).
    public MariaDbTestFactory() => _connectionString = "unused";

    public MariaDbTestFactory(string connectionString) => _connectionString = connectionString;

    static MariaDbTestFactory()
    {
        // Mesmo contrato do SufficitIdentityTestFactory: Development + HTTP,
        // para que o STS aceite certificados efêmeros e não exija HTTPS.
        Environment.SetEnvironmentVariable("ASPNETCORE_ENVIRONMENT", "Development");
        Environment.SetEnvironmentVariable("ASPNETCORE_URLS", null);
    }

    protected override IHostBuilder CreateHostBuilder() => Host.CreateDefaultBuilder();

    protected override void ConfigureWebHost(IWebHostBuilder builder)
    {
        builder.UseContentRoot(AppContext.BaseDirectory);
        builder.UseEnvironment(Environments.Development);

        builder.ConfigureAppConfiguration((_, config) =>
        {
            config.AddInMemoryCollection(new Dictionary<string, string?>
            {
                ["ConnectionStrings:DefaultConnection"] = _connectionString,
                ["Sufficit:Identity:Issuer"] = "https://sts.tests.local",
                ["Sufficit:Identity:LegacyGrants:Password"] = "true",
                ["Sufficit:Identity:LegacyGrants:None"] = "true",
                ["Sufficit:Identity:TokenExchange:Enabled"] = "true",
            });
        });

        builder.ConfigureServices((context, services) =>
        {
            services.AddSufficitIdentitySTS(context.Configuration);
            services.AddControllers()
                .AddApplicationPart(typeof(Sufficit.Identity.STS.Controllers.AuthorizationController).Assembly);
            services.AddAntiforgery();
        });

        builder.Configure(app =>
        {
            app.UseRouting();
            app.UseAuthentication();
            app.UseAuthorization();
            app.UseEndpoints(endpoints => endpoints.MapControllers());
        });
    }

    async Task IAsyncLifetime.InitializeAsync()
    {
        // O schema já vem do SQL canônico aplicado pelo teste; aqui só seededamos
        // os clients/scopes do OpenIddict via TestDataSeeder (idempotente).
        using var scope = Services.CreateScope();
        await TestDataSeeder.SeedAsync(scope.ServiceProvider);
    }

    Task IAsyncLifetime.DisposeAsync() => Task.CompletedTask;
}
