using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.Data.Sqlite;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Options;
using System.Security.Cryptography.X509Certificates;
using Sufficit.Identity.Core.Data;
using Sufficit.Identity.Management;
using Sufficit.Identity.Management.Authorization;
using Sufficit.Identity.STS;
using Sufficit.Identity.Vault;
using Xunit;

namespace Sufficit.Identity.Tests.Infrastructure;

/// <summary>
/// Isolated <see cref="WebApplicationFactory{TEntryPoint}"/> that wires BOTH the
/// STS module and the optional Management API (unlike the shared
/// <see cref="SufficitIdentityTestFactory"/>, which deliberately excludes the
/// management module). Used by <c>ClientsControllerTests</c> to exercise the
/// management REST endpoints over real HTTP.
/// </summary>
/// <remarks>
/// <b>Authorization bypassed.</b> <c>ClientsController</c> carries a hardcoded
/// <c>[Authorize(Policy = "sufficit-identity-management")]</c>, and that policy
/// is registered by <c>AddSufficitIdentityManagement</c> only when
/// <c>RequireAuthorization=true</c> — so setting <c>false</c> does NOT open the
/// endpoint (it makes the policy unresolvable, which throws). Instead, this
/// factory keeps the policy registered but replaces the real
/// <c>ScopeHandler</c> with an <c>AlwaysSucceedHandler</c>, so the endpoints are
/// reachable without minting a full OAuth token. Validating the real authz gate
/// (and adding MFA to it) is item 5.2 in a later wave; the override here is
/// scoped to this test factory only and does NOT touch production code.
/// </remarks>
public sealed class ManagementTestFactory : WebApplicationFactory<ManagementTestFactory>, IAsyncLifetime
{
    private readonly SqliteConnection _connection = new("DataSource=:memory:");
    private readonly bool _bypassAuthz;
    private readonly IReadOnlyDictionary<string, string?>? _extraConfiguration;
    private readonly bool _enablePersonalVaultTestSurface;
    private string? _routePrefix;

    /// <summary>
    /// Creates a factory that does NOT bypass authorization — the real
    /// <c>ScopeHandler</c> runs, so requests without the admin scope get
    /// <c>401/403</c>. Used by the authz-negative test (eval: test-coverage
    /// gap). The default constructor bypasses authz for logic tests.
    /// </summary>
    public static ManagementTestFactory CreateWithRealAuthz()
    {
        var factory = new ManagementTestFactory(bypassAuthz: false);
        return factory;
    }

    public static ManagementTestFactory CreateWithRoutePrefix(string routePrefix)
    {
        var factory = new ManagementTestFactory();
        factory._routePrefix = routePrefix;
        return factory;
    }

    public ManagementTestFactory(
        bool bypassAuthz = true,
        IReadOnlyDictionary<string, string?>? extraConfiguration = null,
        bool enablePersonalVaultTestSurface = false)
    {
        _bypassAuthz = bypassAuthz;
        _extraConfiguration = extraConfiguration;
        _enablePersonalVaultTestSurface = enablePersonalVaultTestSurface;
        _connection.Open();
        // Same UTC_TIMESTAMP shim as SufficitIdentityTestFactory: the legacy
        // Timestamp default uses UTC_TIMESTAMP(), while CreatedAtUtc uses the
        // microsecond-precision UTC_TIMESTAMP(6) form in MariaDB.
        _connection.CreateFunction("UTC_TIMESTAMP", () => DateTime.UtcNow);
        _connection.CreateFunction<int, DateTime>(
            "UTC_TIMESTAMP", _ => DateTime.UtcNow);
    }

    static ManagementTestFactory()
    {
        // Mirrors SufficitIdentityTestFactory: Development + HTTP so the STS
        // accepts ephemeral dev certificates and does not require HTTPS.
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
                ["ConnectionStrings:DefaultConnection"] = "unused",
                ["Sufficit:Identity:Issuer"] = "https://sts.tests.local",
                ["Sufficit:Identity:LegacyGrants:Password"] = "true",
                ["Sufficit:Identity:LegacyGrants:None"] = "true",
                ["Sufficit:Identity:TokenExchange:Enabled"] = "true",
                // Management API ON, authorization policy REGISTERED (true) so
                // the [Authorize] attribute resolves — but the handler is
                // swapped below to always succeed. See class-level remarks.
                ["Sufficit:Identity:Management:Enabled"] = "true",
                ["Sufficit:Identity:Management:RequireAuthorization"] = "true",
                ["Sufficit:Identity:Management:RequireMfa"] = "false",
                ["Sufficit:Identity:Management:TemporaryProvisioningToken:Enabled"] = "true",
                ["Sufficit:Identity:Management:TemporaryOperatorToken:Enabled"] = "true",
                ["Sufficit:Identity:Mcp:ImplicitClientIds:0"] =
                    TestDataSeeder.DeviceClientId,
                ["Sufficit:Identity:Mcp:ImplicitClientIds:1"] =
                    TestDataSeeder.PasswordClientId,
            });
            if (!string.IsNullOrWhiteSpace(_routePrefix))
            {
                config.AddInMemoryCollection(new Dictionary<string, string?>
                {
                    ["Sufficit:Identity:Management:RoutePrefix"] = _routePrefix,
                });
            }
            if (_extraConfiguration is { Count: > 0 })
            {
                config.AddInMemoryCollection(_extraConfiguration);
            }
        });

        builder.ConfigureServices((context, services) =>
        {
            services.AddSufficitIdentitySTS(
                context.Configuration,
                secretStore: new TestSecretStore(context.Configuration));
            services.AddSufficitIdentityManagement(context.Configuration);

            // Keep the test host on the Development pass-through key backend,
            // whose database is created after host startup, while letting the
            // personal Vault controller exercise its enabled-only contract.
            // Production never uses this override.
            if (_enablePersonalVaultTestSurface)
            {
                services.AddSingleton(new VaultOptions { Enabled = true });
                services.AddSingleton<IOptions<VaultOptions>>(
                    Options.Create(new VaultOptions { Enabled = true }));
            }

            // Swap the real ScopeHandler for a test-only one that always
            // satisfies the sufficit-identity-management policy, so the
            // endpoints are reachable without a real OAuth token. Scoped to
            // this factory only. Skipped when _bypassAuthz is false (real-authz
            // test variant).
            if (_bypassAuthz)
            {
                services.RemoveAll<IAuthorizationHandler>();
                services.AddSingleton<IAuthorizationHandler, AlwaysSucceedHandler>();
                services.RemoveAll<IManagementAuthorizationEvaluator>();
                services.AddSingleton<IManagementAuthorizationEvaluator,
                    AlwaysAllowManagementAuthorizationEvaluator>();
                services.RemoveAll<IManagementEntitlementResolver>();
                services.AddSingleton<IManagementEntitlementResolver,
                    AllManagementEntitlementsResolver>();
            }

            ReplaceDatabaseWithSqlite(services, _connection);
            BootstrapSchema();
        });

        builder.Configure(app =>
        {
            // TestServer has no TLS handshake. Project a DER certificate from
            // a test-only header onto the connection so OpenIddict exercises
            // its real mTLS extraction and validation handlers.
            app.Use(async (context, next) =>
            {
                const string headerName =
                    "X-Sufficit-Test-Client-Certificate";
                if (context.Request.Headers.TryGetValue(
                        headerName,
                        out var encodedCertificate)
                    && !string.IsNullOrWhiteSpace(encodedCertificate))
                {
                    try
                    {
                        context.Connection.ClientCertificate =
                            X509CertificateLoader.LoadCertificate(
                                Convert.FromBase64String(encodedCertificate!));
                    }
                    catch (FormatException)
                    {
                        context.Response.StatusCode =
                            StatusCodes.Status400BadRequest;
                        return;
                    }
                }

                await next();
            });

            var configuration = app.ApplicationServices.GetRequiredService<IConfiguration>();
            app.UseSufficitSecurityHeaders(configuration);

            app.UseRouting();
            app.UseAuthentication();
            app.UseAuthorization();

            app.UseEndpoints(endpoints => endpoints.MapControllers());

            // Map the management endpoints under their configured prefix
            // (default "api"), exactly as src/server/Program.cs does.
            // UseSufficitIdentityManagementEndpoints does its own MapWhen +
            // branch (UseRouting/UseEndpoints) internally, so it must run on
            // the app pipeline, not inside a UseEndpoints callback.
            app.UseSufficitIdentityManagementEndpoints(configuration);
        });
    }

    private static void ReplaceDatabaseWithSqlite(IServiceCollection services, SqliteConnection connection)
    {
        // Same descriptor-scrubbing rationale as SufficitIdentityTestFactory.
        var descriptorsToRemove = services
            .Where(d => d.ServiceType == typeof(AppDbContext)
                || (d.ServiceType.IsGenericType && d.ServiceType.GetGenericArguments().Contains(typeof(AppDbContext))))
            .ToList();
        foreach (var descriptor in descriptorsToRemove)
        {
            services.Remove(descriptor);
        }

        // AddDbContextFactory registers both the singleton factory (for the
        // session ITicketStore) and a scoped AppDbContext. Using AddDbContext
        // alongside it causes a captive-dependency fault; the factory is the
        // single registration point. See AddSufficitIdentitySTS for rationale.
        services.AddDbContextFactory<AppDbContext>(db =>
        {
            db.UseSqlite(connection);
            db.UseOpenIddict();
        });
    }

    /// <summary>
    /// Cria o schema ANTES do host subir.
    /// </summary>
    /// <remarks>
    /// Os <c>IHostedService</c> começam antes de
    /// <see cref="IAsyncLifetime.InitializeAsync"/>, onde o
    /// <c>EnsureCreatedAsync</c> ficava — então a retenção de auditoria e o
    /// anel de chaves do DataProtection consultavam tabelas inexistentes no
    /// arranque de TODO teste de gestão. Não era teoria: os logs mostravam
    /// <c>no such table: managementauditevents</c> e
    /// <c>no such table: dataprotectionkeys</c> em toda execução. O primeiro só
    /// virava aviso engolido; o segundo é pior, porque o rascunho de cliente é
    /// guardado com DataProtection, e uma chave que não persistiu no arranque
    /// não é necessariamente a que vai desproteger depois.
    /// <para>
    /// O factory do STS já resolvia isto exatamente assim; este nunca adotou.
    /// A chamada em <c>InitializeAsync</c> continua, idempotente, porque é ela
    /// que semeia os dados de teste.
    /// </para>
    /// </remarks>
    private void BootstrapSchema()
    {
        var options = new DbContextOptionsBuilder<AppDbContext>()
            .UseSqlite(_connection)
            .UseOpenIddict()
            .Options;
        using var database = new AppDbContext(options);
        database.Database.EnsureCreated();
    }

    async Task IAsyncLifetime.InitializeAsync()
    {
        using var scope = Services.CreateScope();
        var db = scope.ServiceProvider.GetRequiredService<AppDbContext>();
        await db.Database.EnsureCreatedAsync();
        await TestDataSeeder.SeedAsync(scope.ServiceProvider);
    }

    Task IAsyncLifetime.DisposeAsync() => Task.CompletedTask;

    protected override void Dispose(bool disposing)
    {
        base.Dispose(disposing);
        if (disposing)
        {
            _connection.Dispose();
        }
    }
}

/// <summary>
/// Test-only <see cref="IAuthorizationHandler"/> that satisfies EVERY
/// requirement, so the <c>sufficit-identity-management</c> policy (which
/// normally requires an authenticated user carrying the admin scope) passes
/// without a real OAuth token. Registered only by <see cref="ManagementTestFactory"/>.
/// </summary>
file sealed class AlwaysSucceedHandler : IAuthorizationHandler
{
    public Task HandleAsync(AuthorizationHandlerContext context)
    {
        foreach (var requirement in context.PendingRequirements.ToList())
        {
            context.Succeed(requirement);
        }
        return Task.CompletedTask;
    }
}

file sealed class AlwaysAllowManagementAuthorizationEvaluator
    : IManagementAuthorizationEvaluator
{
    public ValueTask<ManagementAuthorizationDecision> EvaluateAsync(
        System.Security.Claims.ClaimsPrincipal principal,
        string capability,
        ManagementResource resource,
        CancellationToken cancellationToken = default) =>
        ValueTask.FromResult(ManagementAuthorizationDecision.Allowed());
}

file sealed class AllManagementEntitlementsResolver
    : IManagementEntitlementResolver
{
    public ValueTask<ManagementEntitlements> ResolveAsync(
        System.Security.Claims.ClaimsPrincipal principal,
        CancellationToken cancellationToken = default) =>
        ValueTask.FromResult(
            new ManagementEntitlements(ManagementCapabilities.All));
}
