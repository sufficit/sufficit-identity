using System.Data.Common;
using Microsoft.AspNetCore.Antiforgery;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Diagnostics.HealthChecks;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.AspNetCore.RateLimiting;
using Microsoft.AspNetCore.TestHost;
using Microsoft.Data.Sqlite;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Diagnostics;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using System.Security.Cryptography.X509Certificates;
using System.Threading.RateLimiting;
using Sufficit.Identity.Core.Data;
using Sufficit.Identity.Core.Entities;
using Sufficit.Identity.Management;
using Sufficit.Identity.Server;
using Sufficit.Identity.STS;
using Sufficit.Identity.STS.Controllers;
using OpenIddict.Validation.AspNetCore;
using Xunit;

namespace Sufficit.Identity.Tests.Infrastructure;

/// <summary>
/// Custom <see cref="WebApplicationFactory{TEntryPoint}"/> for the Sufficit
/// Identity STS.
///
/// <para>
/// <b>Why not <c>WebApplicationFactory&lt;Program&gt;</c>:</b> src/server/Program.cs
/// uses top-level statements, which the compiler turns into an
/// <c>internal sealed partial class Program</c> — invisible to this separate
/// test assembly. More importantly, these tests exercise the STS API module
/// in isolation from the composition host's UI and management modules. This
/// factory reproduces the minimal wiring it needs
/// (<c>AddSufficitIdentitySTS</c> + health checks) directly against the generic
/// host. <see cref="SufficitIdentityTestFactory"/> is used as its own
/// <c>TEntryPoint</c> purely so <see cref="WebApplicationFactory{TEntryPoint}"/>
/// has *some* assembly to resolve a (unused) content root from; all real
/// wiring happens in <see cref="ConfigureWebHost"/> below, which is the
/// officially documented extension point for hosts without a usable
/// reflection-discoverable entry point.
/// </para>
/// <para>
/// The production DB registration (MySQL via <c>ServerVersion.AutoDetect</c>)
/// is swapped for a per-factory temporary SQLite database so tests never
/// touch a real database or trigger the MySQL auto-detect handshake. Each
/// context opens its own connection, which preserves the intentional
/// concurrent requests exercised by protocol race-condition tests.
/// </para>
/// </summary>
public sealed class SufficitIdentityTestFactory : WebApplicationFactory<SufficitIdentityTestFactory>, IAsyncLifetime
{
    private static readonly SqliteUtcTimestampInterceptor SqliteFunctions = new();

    private readonly string _databasePath = Path.Combine(
        Path.GetTempPath(),
        $"sufficit-identity-tests-{Guid.NewGuid():N}.db");
    private IReadOnlyDictionary<string, string?>? _extraConfiguration;

    private string DatabaseConnectionString => new SqliteConnectionStringBuilder
    {
        DataSource = _databasePath,
        Mode = SqliteOpenMode.ReadWriteCreate,
        Cache = SqliteCacheMode.Shared,
        Pooling = false,
        DefaultTimeout = 30,
    }.ToString();

    /// <summary>
    /// Builds a factory with additional configuration overlaid on top of the
    /// base in-memory configuration below (e.g.
    /// <c>Sufficit:Identity:TokenExchange:AllowedClientIds</c>, to exercise
    /// the allowlist-rejection branch). Every OTHER test class shares ONE
    /// parameterless-constructed instance via <see cref="StsCollection"/>,
    /// seeded once — this is only for the rare test that needs a config
    /// value that shared instance intentionally doesn't set, and therefore
    /// needs its own, separate instance (own fresh temporary SQLite
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
        // AddSufficitIdentitySTS (src/sts/ServiceCollectionExtensions.cs) reads
        // ASPNETCORE_ENVIRONMENT directly from the process environment (not the
        // generic host's IHostEnvironment abstraction) to decide whether to fall
        // back to ephemeral development signing/encryption certificates and to
        // disable the HTTPS-only transport security requirement. TestServer is
        // plain HTTP, so both are required. Must be set before the host is built
        // (that code runs synchronously inside AddServer(...) during
        // ConfigureServices).
        Environment.SetEnvironmentVariable("ASPNETCORE_ENVIRONMENT", "Development");
        Environment.SetEnvironmentVariable("ASPNETCORE_URLS", null);
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
                // EVALUATION-2026-07-21 §5 P0 #8 — defaults flipped to false
                // (secure-by-default). Tests that exercise these grants explicitly
                // need to opt back in, mirroring what a real environment that
                // still needs them would do via appsettings.<env>.json.
                ["Sufficit:Identity:LegacyGrants:Password"] = "true",
                ["Sufficit:Identity:LegacyGrants:None"] = "true",
                ["Sufficit:Identity:TokenExchange:Enabled"] = "true",
                // The shared fixture exercises legacy account/token flows
                // without manufacturing a fresh-authentication claim for
                // every test. Production keeps the secure defaults; tests
                // that cover Enforce provide an explicit override below.
                ["Sufficit:Identity:CredentialMutations:StepUpMode"] = "Audit",
                ["Sufficit:Identity:PersonalTokens:Mode"] = "Observe",
                ["Sufficit:Identity:PersonalTokens:RequiredScope"] = "",
                ["Sufficit:Identity:PersonalTokens:RequireRecentAuthentication"] = "false",
                // Which clients are implicitly entitled to identity.mcp is
                // deployment configuration with no built-in default, so the
                // fixture states it the way a real deployment would.
                ["Sufficit:Identity:Mcp:ImplicitClientIds:0"] =
                    TestDataSeeder.DeviceClientId,
                ["Sufficit:Identity:Mcp:ImplicitClientIds:1"] =
                    TestDataSeeder.PasswordClientId,
                // NOTE: the product scope and its entitlement are deliberately
                // ABSENT here. They are seeded into the database by
                // TestDataSeeder, the way a deployment's provisioning manifest
                // declares them, so the suite proves the database path works
                // with no configuration at all (eval 2026-08-30, F-2).
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
            services.AddSufficitIdentitySTS(
                context.Configuration,
                secretStore: new TestSecretStore(context.Configuration));
            services.AddSufficitCors(
                context.Configuration.GetSection("Sufficit:Identity:Cors")
                    .Get<CorsOptions>() ?? new CorsOptions());

            ReplaceDatabaseWithSqlite(services, DatabaseConnectionString);

            // AuthorizationController lives in the STS assembly, which is not
            // this factory's "entry" assembly, so MVC's default application part
            // discovery never finds it — register it explicitly, exactly like
            // Sufficit.Identity.UI registers its own controllers in
            // AddSufficitIdentityUI.
            services.AddControllers()
                .AddApplicationPart(typeof(AuthorizationController).Assembly);

            services.AddHealthChecks()
                .AddDbContextCheck<AppDbContext>("database");

            // Defensive: src/server/Program.cs registers MVC via AddControllers()
            // only (no AddMvc/AddRazorPages), and this factory does not
            // reproduce Program.cs line-for-line (see the class doc above),
            // so whether antiforgery services end up registered as a side
            // effect is not guaranteed. DeviceController takes a hard
            // dependency on IAntiforgery, and the test-only "/test-only/
            // antiforgery" endpoint below needs it too — AddAntiforgery()'s
            // registrations are TryAdd-based, so calling it again here is a
            // harmless no-op if Program.cs's real wiring already added it.
            services.AddAntiforgery();

            services.AddAuthorization(options =>
            {
                options.AddPolicy("test-management-access", policy =>
                {
                    policy.AuthenticationSchemes.Add(
                        OpenIddictValidationAspNetCoreDefaults.AuthenticationScheme);
                    policy.RequireAuthenticatedUser();
                    policy.Requirements.Add(
                        new ScopeRequirement("identity.management"));
                    policy.Requirements.Add(new MfaRequirement());
                    policy.RequireRole("manager");
                });
            });
            services.AddSingleton<IAuthorizationHandler, ScopeHandler>();
            services.AddSingleton<IAuthorizationHandler, MfaHandler>();

            // The integration factory registers a MINIMAL limiter: it only has
            // to resolve the "device-information" named policy so endpoints that
            // reference it activate, and provide UseRateLimiter() a limiter to
            // run. The production credential/admin/PAR/device partitioning is a
            // singleton keyed on RemoteIpAddress — null under TestServer, so
            // every test in the shared collection would share one partition and
            // throttle each other. That production logic is covered directly
            // instead: IdentityRateLimitPolicyTests exercises the classification,
            // and RateLimiterServiceCollectionExtensionsTests drives the real
            // AddSufficitIdentityRateLimiter partitions through DefaultHttpContext
            // (eval 2026-08-30, architecture item 1).
            var rateLimit = context.Configuration
                .GetSection("Sufficit:Identity:RateLimit")
                .Get<RateLimitOptions>() ?? new RateLimitOptions();
            services.AddRateLimiter(options =>
            {
                options.RejectionStatusCode =
                    StatusCodes.Status429TooManyRequests;
                options.AddPolicy("device-information", httpContext =>
                    RateLimitPartition.GetFixedWindowLimiter(
                        httpContext.Connection.RemoteIpAddress?.ToString()
                            ?? "unknown",
                        _ => new FixedWindowRateLimiterOptions
                        {
                            PermitLimit = rateLimit.DeviceInformationPermitLimit,
                            Window = TimeSpan.FromSeconds(
                                rateLimit.DeviceInformationWindowSeconds),
                            QueueLimit = 0,
                            AutoReplenishment = true,
                        }));
            });
        });

        builder.Configure(app =>
        {
            // TestServer does not perform a TLS handshake, so integration
            // tests cannot populate Connection.ClientCertificate naturally.
            // This test-only bridge accepts a DER certificate and projects it
            // onto the connection before the real mTLS policy runs. The
            // production host never registers this middleware.
            app.Use(async (context, next) =>
            {
                const string headerName = "X-Sufficit-Test-Client-Certificate";
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
                        context.Response.StatusCode = StatusCodes.Status400BadRequest;
                        return;
                    }
                }

                await next();
            });

            // Same security-headers middleware (incl. CSP) as the composition
            // host's Program.cs — exercised here so CspHeaderTests can assert
            // the header is emitted without a separate Program.cs-reproducing
            // factory. See SecurityHeadersMiddlewareExtensions. IConfiguration
            // is resolved from the built provider (the Configure(app) overload
            // has no context parameter, unlike ConfigureServices).
            var configuration = app.ApplicationServices.GetRequiredService<Microsoft.Extensions.Configuration.IConfiguration>();
            app.UseSufficitSecurityHeaders(configuration);

            app.UseRouting();
            app.UseRateLimiter();
            app.UseSufficitCors(
                app.ApplicationServices.GetRequiredService<SufficitIdentityOptions>().Cors);

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
                // TEST-ONLY endpoints (never registered by src/server/Program.cs).
                //
                // The real interactive login/consent/device UI lives in the
                // embedded Sufficit.Identity.UI project (a Blazor Server
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
                // needing the embedded UI project at all.
                // -------------------------------------------------------------

                // POST /test-only/signin  (form fields: username, mfa)
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

                    var additionalClaims = string.Equals(
                        form["mfa"].ToString(),
                        "true",
                        StringComparison.OrdinalIgnoreCase)
                            ? new[]
                            {
                                new System.Security.Claims.Claim("amr", "pwd"),
                                new System.Security.Claims.Claim("amr", "otp"),
                                new System.Security.Claims.Claim("amr", "mfa"),
                                new System.Security.Claims.Claim(
                                    "auth_time",
                                    DateTimeOffset.UtcNow.ToUnixTimeSeconds()
                                        .ToString(System.Globalization.CultureInfo.InvariantCulture)),
                                new System.Security.Claims.Claim(
                                    "acr",
                                    "urn:sufficit:acr:loa2"),
                            }
                            : [];

                    await signInManager.SignInWithClaimsAsync(
                        user,
                        isPersistent: false,
                        additionalClaims);
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

                endpoints.MapGet(
                        "/test-only/management-access",
                        () => Results.NoContent())
                    .RequireAuthorization("test-management-access");
            });
        });
    }

    private static void ReplaceDatabaseWithSqlite(
        IServiceCollection services,
        string connectionString)
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

        // AddDbContextFactory registers both the singleton factory (for the
        // session ITicketStore) and a scoped AppDbContext. Using AddDbContext
        // alongside it causes a captive-dependency fault; the factory is the
        // single registration point. See AddSufficitIdentitySTS for rationale.
        services.AddDbContextFactory<AppDbContext>(db =>
        {
            db.UseSqlite(connectionString);
            db.AddInterceptors(SqliteFunctions);
            db.UseOpenIddict();
        });

        // The vault KEK readiness probe is an IHostedService and therefore
        // starts before IAsyncLifetime.InitializeAsync().  Persisted
        // DataProtection keys use the same AppDbContext, so the probe must
        // see its table before the host starts.  Bootstrap the SQLite schema
        // here (the later EnsureCreatedAsync call remains idempotent and still
        // seeds the test data after the host is ready).
        var bootstrapOptions = new DbContextOptionsBuilder<AppDbContext>()
            .UseSqlite(connectionString)
            .AddInterceptors(SqliteFunctions)
            .UseOpenIddict()
            .Options;
        using var bootstrapDb = new AppDbContext(bootstrapOptions);
        bootstrapDb.Database.EnsureCreated();
        bootstrapDb.Database.OpenConnection();
        using var command = bootstrapDb.Database.GetDbConnection().CreateCommand();
        command.CommandText = "PRAGMA journal_mode=WAL;";
        _ = command.ExecuteScalar();
        bootstrapDb.Database.CloseConnection();
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
        // Dispose the host first so every context releases its file handle,
        // then remove the per-factory test database and its WAL sidecars.
        base.Dispose(disposing);

        if (disposing)
        {
            DeleteDatabaseFile(_databasePath);
            DeleteDatabaseFile(_databasePath + "-shm");
            DeleteDatabaseFile(_databasePath + "-wal");
        }
    }

    private static void DeleteDatabaseFile(string path)
    {
        if (File.Exists(path))
        {
            File.Delete(path);
        }
    }

    private sealed class SqliteUtcTimestampInterceptor : DbConnectionInterceptor
    {
        public override void ConnectionOpened(
            DbConnection connection,
            ConnectionEndEventData eventData) => RegisterFunctions(connection);

        public override Task ConnectionOpenedAsync(
            DbConnection connection,
            ConnectionEndEventData eventData,
            CancellationToken cancellationToken = default)
        {
            RegisterFunctions(connection);
            return Task.CompletedTask;
        }

        private static void RegisterFunctions(DbConnection connection)
        {
            if (connection is not SqliteConnection sqlite)
            {
                return;
            }

            // The production model uses MariaDB's UTC_TIMESTAMP defaults.
            // Register the same name on every independently opened SQLite
            // connection so inserts remain faithful to that model.
            sqlite.CreateFunction("UTC_TIMESTAMP", () => DateTime.UtcNow);
            sqlite.CreateFunction<int, DateTime>(
                "UTC_TIMESTAMP", _ => DateTime.UtcNow);
        }
    }
}
