using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.Data.Sqlite;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.Extensions.Hosting;
using Sufficit.Identity.Core.Data;
using Sufficit.Identity.Management;
using Sufficit.Identity.Management.Authorization;
using Sufficit.Identity.STS;
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

    public ManagementTestFactory(bool bypassAuthz = true)
    {
        _bypassAuthz = bypassAuthz;
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
            });
        });

        builder.ConfigureServices((context, services) =>
        {
            services.AddSufficitIdentitySTS(context.Configuration);
            services.AddSufficitIdentityManagement(context.Configuration);

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
            }

            ReplaceDatabaseWithSqlite(services, _connection);
        });

        builder.Configure(app =>
        {
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

        services.AddDbContext<AppDbContext>(db =>
        {
            db.UseSqlite(connection);
            db.UseOpenIddict();
        });
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
