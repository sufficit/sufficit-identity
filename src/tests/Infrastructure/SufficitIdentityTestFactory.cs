using Microsoft.AspNetCore.Antiforgery;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Diagnostics.HealthChecks;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.AspNetCore.TestHost;
using Microsoft.Data.Sqlite;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Sufficit.Identity.Core.Data;
using Sufficit.Identity.Core.Entities;
using Sufficit.Identity.Server;
using Sufficit.Identity.STS.Controllers;
using Xunit;

namespace Sufficit.Identity.Tests.Infrastructure;

/// <summary>
/// Custom <see cref="WebApplicationFactory{TEntryPoint}"/> for the Sufficit
/// Identity STS.
///
/// <para>
/// <b>Why not <c>WebApplicationFactory&lt;Program&gt;</c>:</b> src/sts/Program.cs
/// uses top-level statements, which the compiler turns into an
/// <c>internal sealed partial class Program</c> — invisible to this separate
/// test assembly without an <c>InternalsVisibleTo</c> attribute added to the
/// STS project. Editing src/sts is out of scope for this test project, so
/// instead of touching Program.cs this factory replicates the minimal host
/// wiring Program.cs itself performs (<c>AddSufficitIdentitySTS</c> + the
/// <c>/connect/*</c> MVC controllers + health checks), directly against the
/// generic host. <see cref="SufficitIdentityTestFactory"/> is used as its own
/// <c>TEntryPoint</c> purely so <see cref="WebApplicationFactory{TEntryPoint}"/>
/// has *some* assembly to resolve a (unused) content root from; all real
/// wiring happens in <see cref="ConfigureWebHost"/> below, which is the
/// officially documented extension point for hosts without a usable
/// reflection-discoverable entry point.
/// </para>
/// <para>
/// The production DB registration (MySQL via <c>ServerVersion.AutoDetect</c>)
/// is swapped for a single, held-open SQLite in-memory connection so tests
/// never touch a real database and never trigger the MySQL auto-detect
/// handshake.
/// </para>
/// </summary>
public sealed class SufficitIdentityTestFactory : WebApplicationFactory<SufficitIdentityTestFactory>, IAsyncLifetime
{
    private readonly SqliteConnection _connection = new("DataSource=:memory:");
    private IReadOnlyDictionary<string, string?>? _extraConfiguration;

    /// <summary>
    /// Builds a factory with additional configuration overlaid on top of the
    /// base in-memory configuration below (e.g.
    /// <c>Sufficit:Identity:TokenExchange:AllowedClientIds</c>, to exercise
    /// the allowlist-rejection branch). Every OTHER test class shares ONE
    /// parameterless-constructed instance via <see cref="StsCollection"/>,
    /// seeded once — this is only for the rare test that needs a config
    /// value that shared instance intentionally doesn't set, and therefore
    /// needs its own, separate instance (own fresh in-memory SQLite
    /// database) instead.
    /// </summary>
    /// <remarks>
    /// Deliberately a static factory method rather than a constructor
    /// overload/optional parameter: xUnit's <see cref="ICollectionFixture{TFixture}"/>
    /// instantiates <see cref="SufficitIdentityTestFactory"/> by reflecting
    /// over its constructor and resolving EVERY parameter as a fixture —
    /// including ones with a C# default value, which xUnit does not
    /// special-case — so an optional constructor parameter with no matching
    /// registered fixture breaks the shared fixture with "had one or more
    /// unresolved constructor arguments". Setting <see cref="_extraConfiguration"/>
    /// here works because it is only ever READ later, from
    /// <see cref="ConfigureWebHost"/>, which runs lazily on first access of
    /// <see cref="WebApplicationFactory{TEntryPoint}.Services"/> — i.e.
    /// strictly after this method returns.
    /// </remarks>
    public static SufficitIdentityTestFactory CreateIsolated(IReadOnlyDictionary<string, string?> extraConfiguration)
    {
        var factory = new SufficitIdentityTestFactory();
        factory._extraConfiguration = extraConfiguration;
        return factory;
    }

    public SufficitIdentityTestFactory()
    {
        // AddSufficitIdentitySTS (src/server/ServiceCollectionExtensions.cs) reads
        // ASPNETCORE_ENVIRONMENT directly from the process environment (not the
        // generic host's IHostEnvironment abstraction) to decide whether to fall
        // back to ephemeral development signing/encryption certificates and to
        // disable the HTTPS-only transport security requirement. TestServer is
        // plain HTTP, so both are required. Must be set before the host is built
        // (that code runs synchronously inside AddServer(...) during
        // ConfigureServices).
        Environment.SetEnvironmentVariable("ASPNETCORE_ENVIRONMENT", "Development");
        Environment.SetEnvironmentVariable("ASPNETCORE_URLS", null);

        _connection.Open();

        // AppDbContext maps ApplicationUser.Timestamp with
        // HasDefaultValueSql("UTC_TIMESTAMP()") — a MySQL-only function. SQLite
        // has no such builtin; register it as a user-defined function on the
        // connection so inserts that rely on the DB-generated default (i.e. every
        // UserManager.CreateAsync call) succeed unmodified.
        _connection.CreateFunction("UTC_TIMESTAMP", () => DateTime.UtcNow);
    }

    // Bypasses WebApplicationFactory's default reflection-based discovery of a
    // `Program`/`CreateHostBuilder` entry point (which would fail: this
    // assembly has neither). The base class still wraps whatever is returned
    // here with its own ConfigureWebHost(...) call (see below) and attaches
    // the TestServer.
    protected override IHostBuilder CreateHostBuilder() => Host.CreateDefaultBuilder();

    protected override void ConfigureWebHost(IWebHostBuilder builder)
    {
        // WebApplicationFactory's default content-root auto-detection walks up
        // from the test assembly's directory looking for a sibling folder named
        // after the assembly ("Sufficit.Identity.Tests") — which doesn't exist
        // (the project directory is src/tests). Point it at the test binary's
        // own output directory instead; nothing in this host reads physical
        // content files (no wwwroot, no appsettings.json — all configuration is
        // supplied in-memory below), so any existing directory works.
        builder.UseContentRoot(AppContext.BaseDirectory);
        builder.UseEnvironment(Environments.Development);

        builder.ConfigureAppConfiguration((_, config) =>
        {
            config.AddInMemoryCollection(new Dictionary<string, string?>
            {
                // AddSufficitIdentitySTS reads this eagerly (throws if missing).
                // The value itself is irrelevant: the MySQL DbContextOptions it
                // registers is fully replaced below before anything resolves it.
                ["ConnectionStrings:DefaultConnection"] = "unused",
                ["Sufficit:Identity:Issuer"] = "https://sts.tests.local",
            });

            // Layered on top so a per-test override (e.g. a restricted
            // Sufficit:Identity:TokenExchange:AllowedClientIds) can win over
            // the defaults above — see the constructor's XML doc.
            if (_extraConfiguration is { Count: > 0 })
            {
                config.AddInMemoryCollection(_extraConfiguration);
            }
        });

        builder.ConfigureServices((context, services) =>
        {
            services.AddSufficitIdentitySTS(context.Configuration);

            ReplaceDatabaseWithSqlite(services, _connection);

            // AuthorizationController lives in the STS assembly, which is not
            // this factory's "entry" assembly, so MVC's default application part
            // discovery never finds it — register it explicitly, exactly like
            // Sufficit.Identity.UI registers its own controllers in
            // AddSufficitIdentityUI.
            services.AddControllers()
                .AddApplicationPart(typeof(AuthorizationController).Assembly);

            services.AddHealthChecks()
                .AddDbContextCheck<AppDbContext>("database");

            // Defensive: src/sts/Program.cs registers MVC via AddControllers()
            // only (no AddMvc/AddRazorPages), and this factory does not
            // reproduce Program.cs line-for-line (see the class doc above),
            // so whether antiforgery services end up registered as a side
            // effect is not guaranteed. DeviceController takes a hard
            // dependency on IAntiforgery, and the test-only "/test-only/
            // antiforgery" endpoint below needs it too — AddAntiforgery()'s
            // registrations are TryAdd-based, so calling it again here is a
            // harmless no-op if Program.cs's real wiring already added it.
            services.AddAntiforgery();
        });

        builder.Configure(app =>
        {
            app.UseRouting();

            app.UseAuthentication();
            app.UseAuthorization();

            app.UseEndpoints(endpoints =>
            {
                endpoints.MapControllers();

                endpoints.MapHealthChecks("/health", new HealthCheckOptions
                {
                    Predicate = _ => false
                });
                endpoints.MapHealthChecks("/health/ready");

                // -------------------------------------------------------------
                // TEST-ONLY endpoints (never registered by src/sts/Program.cs).
                //
                // The real interactive login/consent/device UI lives in the
                // sibling sufficit-identity-ui repo (a separate Blazor Server
                // project), which this factory deliberately does not pull in
                // (see the class doc above). Driving the authorization_code
                // and device_code flows end-to-end still requires a genuine
                // signed-in cookie principal (AuthorizationController.
                // Authorize / DeviceController.Verify both call
                // HttpContext.AuthenticateAsync() against the ASP.NET Core
                // Identity application cookie) and, for the device
                // verification POST specifically, a valid antiforgery token
                // pair. These two endpoints are minimal, test-only stand-ins
                // for "log in" and "fetch an antiforgery token" so integration
                // tests can exercise those controllers over real HTTP without
                // needing the sibling UI project at all.
                // -------------------------------------------------------------

                // POST /test-only/signin  (form field: username)
                // Signs the named user into the SAME cookie authentication
                // scheme (Identity.Application) that AuthorizationController
                // and DeviceController check via HttpContext.AuthenticateAsync().
                endpoints.MapPost("/test-only/signin", async context =>
                {
                    var form = await context.Request.ReadFormAsync();
                    var username = form["username"].ToString();

                    var userManager = context.RequestServices.GetRequiredService<UserManager<ApplicationUser>>();
                    var signInManager = context.RequestServices.GetRequiredService<SignInManager<ApplicationUser>>();

                    var user = await userManager.FindByNameAsync(username) ??
                        throw new InvalidOperationException($"Test user '{username}' not found.");

                    await signInManager.SignInAsync(user, isPersistent: false);
                    context.Response.StatusCode = StatusCodes.Status200OK;
                });

                // GET /test-only/antiforgery
                // Issues a real antiforgery token pair (cookie on the response
                // + request token in the JSON body), exactly as a server-
                // rendered form's <AntiforgeryToken/> would, so a test can
                // include "__RequestVerificationToken" on a subsequent POST
                // (e.g. to ~/connect/device) the same way the real UI form does.
                endpoints.MapGet("/test-only/antiforgery", (HttpContext context, IAntiforgery antiforgery) =>
                {
                    var tokens = antiforgery.GetAndStoreTokens(context);
                    return Results.Json(new { requestToken = tokens.RequestToken });
                });
            });
        });
    }

    private static void ReplaceDatabaseWithSqlite(IServiceCollection services, SqliteConnection connection)
    {
        // Modern EF Core doesn't just register a single DbContextOptions<T>
        // descriptor: AddDbContext also adds a DbContextOptionsConfiguration<T>
        // entry carrying the actual configure delegate (here, the MySQL
        // UseMySql(...) + ServerVersion.AutoDetect(...) lambda from
        // AddSufficitIdentitySTS), and DbContextOptions<T> is built by
        // replaying *every* registered DbContextOptionsConfiguration<T> — so
        // removing only the DbContextOptions<AppDbContext> descriptor is not
        // enough; the old configuration entry survives and still runs
        // (confirmed: it was still hitting ServerVersion.AutoDetect against the
        // dummy connection string). Remove every descriptor that mentions
        // AppDbContext at all (DbContextOptions<AppDbContext>,
        // DbContextOptionsConfiguration<AppDbContext>, AppDbContext itself,
        // etc.) before re-registering from scratch against SQLite.
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
        // Accessing Services triggers ConfigureWebHost + host build.
        using var scope = Services.CreateScope();
        var db = scope.ServiceProvider.GetRequiredService<AppDbContext>();
        await db.Database.EnsureCreatedAsync();

        await TestDataSeeder.SeedAsync(scope.ServiceProvider);
    }

    Task IAsyncLifetime.DisposeAsync() => Task.CompletedTask;

    protected override void Dispose(bool disposing)
    {
        // Dispose the host first (releases pooled DbContexts/scopes), then the
        // backing SQLite connection they were using.
        base.Dispose(disposing);

        if (disposing)
        {
            _connection.Dispose();
        }
    }
}
