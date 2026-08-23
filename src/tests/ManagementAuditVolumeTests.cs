using Microsoft.Data.Sqlite;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Caching.Memory;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;
using Sufficit.Identity.Core.Data;
using Sufficit.Identity.Core.Entities;
using Sufficit.Identity.Management;
using Sufficit.Identity.Management.Audit;
using Sufficit.Identity.Management.Authorization;
using Xunit;

namespace Sufficit.Identity.Tests;

/// <summary>
/// The management audit table is written on every privileged operation and,
/// on the surfaces that record them, on every refusal — while having had no
/// retention at all. These cover the two bounds that keep it from becoming
/// either a growth problem or a write-amplification one.
/// </summary>
public sealed class ManagementAuditVolumeTests
{
    [Fact]
    public async Task Repeated_identical_denials_are_recorded_once_per_window()
    {
        using var harness = Harness.Create();
        var guard = harness.CreateGuard();
        var context = Harness.Context("operator-1");
        var resource = new ManagementResource(
            ManagementResourceTypes.Client,
            "client-a");

        for (var attempt = 0; attempt < 25; attempt++)
        {
            await Assert.ThrowsAsync<ManagementAccessException>(() =>
                guard.DemandAsync(
                    context,
                    ManagementCapabilities.ClientsUpdate,
                    resource,
                    CancellationToken.None,
                    auditDenial: true));
        }

        // A client looping against a wall it cannot pass must not turn each
        // attempt into a row plus a SaveChanges on the request path.
        Assert.Equal(1, await harness.CountAuditAsync());
    }

    [Fact]
    public async Task Denials_on_distinct_resources_are_each_recorded()
    {
        using var harness = Harness.Create();
        var guard = harness.CreateGuard();
        var context = Harness.Context("operator-1");

        foreach (var clientId in new[] { "client-a", "client-b", "client-c" })
        {
            await Assert.ThrowsAsync<ManagementAccessException>(() =>
                guard.DemandAsync(
                    context,
                    ManagementCapabilities.ClientsUpdate,
                    new ManagementResource(
                        ManagementResourceTypes.Client,
                        clientId),
                    CancellationToken.None,
                    auditDenial: true));
        }

        // Probing across different resources is the pattern worth seeing, so
        // suppression must not collapse it.
        Assert.Equal(3, await harness.CountAuditAsync());
    }

    [Fact]
    public async Task Retention_removes_entries_past_the_configured_window()
    {
        using var harness = Harness.Create();
        await harness.SeedAuditAsync(ageDays: 400, count: 5);
        await harness.SeedAuditAsync(ageDays: 10, count: 3);

        await harness.RunRetentionAsync(retentionDays: 365);

        // Only the recent rows survive; the table no longer grows unbounded.
        Assert.Equal(3, await harness.CountAuditAsync());
    }

    /// <summary>
    /// The short default is a deliberate product decision, not an oversight:
    /// this trail exists to DETECT wrong behavior on an identity service, and
    /// an operator who has not noticed something within a fortnight will not
    /// notice it in month eleven. Pinned so raising it stays a conscious
    /// choice with the trade-off in view (see AuditRetentionDays).
    /// </summary>
    [Fact]
    public void Default_retention_window_is_a_fortnight()
    {
        Assert.Equal(15, new ManagementOptions().AuditRetentionDays);
    }

    [Fact]
    public async Task Retention_at_the_default_window_prunes_older_history()
    {
        using var harness = Harness.Create();
        var retentionDays = new ManagementOptions().AuditRetentionDays;
        await harness.SeedAuditAsync(ageDays: retentionDays + 5, count: 6);
        await harness.SeedAuditAsync(ageDays: 1, count: 2);

        await harness.RunRetentionAsync(retentionDays);

        Assert.Equal(2, await harness.CountAuditAsync());
    }

    [Fact]
    public async Task Retention_disabled_keeps_everything()
    {
        using var harness = Harness.Create();
        await harness.SeedAuditAsync(ageDays: 4000, count: 4);

        await harness.RunRetentionAsync(retentionDays: 0);

        // Zero means a deployment keeps history on purpose.
        Assert.Equal(4, await harness.CountAuditAsync());
    }

    private sealed class Harness : IDisposable
    {
        private readonly ServiceProvider _provider;
        private readonly SqliteConnection _connection;

        private Harness(ServiceProvider provider, SqliteConnection connection)
        {
            _provider = provider;
            _connection = connection;
        }

        public static Harness Create()
        {
            var connection = new SqliteConnection("DataSource=:memory:");
            connection.Open();

            var services = new ServiceCollection();
            services.AddLogging();
            services.AddMemoryCache();
            services.AddDbContextFactory<AppDbContext>(db =>
            {
                db.UseSqlite(connection);
                db.UseOpenIddict();
            });
            var provider = services.BuildServiceProvider();
            using (var db = provider
                .GetRequiredService<IDbContextFactory<AppDbContext>>()
                .CreateDbContext())
            {
                db.Database.EnsureCreated();
            }

            return new Harness(provider, connection);
        }

        public static ManagementRequestContext Context(string subject) =>
            new(
                new System.Security.Claims.ClaimsPrincipal(
                    new System.Security.Claims.ClaimsIdentity(
                        [new System.Security.Claims.Claim("sub", subject)],
                        "test")),
                Guid.NewGuid().ToString("N"));

        public ManagementOperationGuard CreateGuard() =>
            new(
                new AlwaysDeniedEvaluator(),
                _provider.GetRequiredService<IDbContextFactory<AppDbContext>>()
                    .CreateDbContext(),
                _provider.GetRequiredService<IMemoryCache>(),
                NullLogger<ManagementOperationGuard>.Instance);

        public async Task SeedAuditAsync(int ageDays, int count)
        {
            await using var database = await _provider
                .GetRequiredService<IDbContextFactory<AppDbContext>>()
                .CreateDbContextAsync();
            for (var i = 0; i < count; i++)
            {
                database.ManagementAuditEvents.Add(new ManagementAuditEvent
                {
                    OccurredAtUtc = DateTime.UtcNow.AddDays(-ageDays),
                    OperatorSubject = "seed",
                    Capability = ManagementCapabilities.ClientsRead,
                    ResourceType = ManagementResourceTypes.Client,
                    AuthorizationOutcome = "allowed",
                    OperationOutcome = "succeeded",
                    CorrelationId = Guid.NewGuid().ToString("N"),
                });
            }

            await database.SaveChangesAsync();
        }

        public async Task RunRetentionAsync(int retentionDays)
        {
            var worker = new ManagementAuditRetentionWorker(
                _provider.GetRequiredService<IDbContextFactory<AppDbContext>>(),
                Options.Create(new ManagementOptions
                {
                    AuditRetentionDays = retentionDays,
                }),
                NullLogger<ManagementAuditRetentionWorker>.Instance);

            await worker.StartAsync(CancellationToken.None);
            // The worker prunes immediately, then sleeps for its interval.
            await Task.Delay(300);
            await worker.StopAsync(CancellationToken.None);
        }

        public async Task<int> CountAuditAsync()
        {
            await using var database = await _provider
                .GetRequiredService<IDbContextFactory<AppDbContext>>()
                .CreateDbContextAsync();
            return await database.ManagementAuditEvents.CountAsync();
        }

        public void Dispose()
        {
            _provider.Dispose();
            _connection.Dispose();
        }
    }

    private sealed class AlwaysDeniedEvaluator : IManagementAuthorizationEvaluator
    {
        public ValueTask<ManagementAuthorizationDecision> EvaluateAsync(
            System.Security.Claims.ClaimsPrincipal principal,
            string capability,
            ManagementResource resource,
            CancellationToken cancellationToken = default) =>
            ValueTask.FromResult(
                ManagementAuthorizationDecision.Denied("capability_not_granted"));
    }
}
