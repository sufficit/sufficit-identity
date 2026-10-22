using System.Runtime.CompilerServices;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Sufficit.Identity.Core.Data;
using Sufficit.Identity.Core.Metrics;
using Sufficit.Identity.STS.Metrics;
using Xunit;

namespace Sufficit.Identity.Tests;

public sealed class IdentityUsageCountersTests
{
    private static IdentityUsageMetric Metric(string client = "client", DateTime? at = null) => new(
        at ?? DateTime.UtcNow, client, "token_issued", "token", "client_credentials", "succeeded");

    [Fact]
    public void Uses_of_the_same_dimension_become_one_counter()
    {
        var runtime = new IdentityMetricsRuntimeState();
        var counters = new IdentityUsageCounters(runtime);
        var day = new DateTime(2026, 10, 22, 9, 0, 0, DateTimeKind.Utc);

        for (var index = 0; index < 1_000; index++)
            Assert.True(counters.TryRecord(Metric(at: day.AddSeconds(index))));
        Assert.True(counters.TryRecord(Metric("other", day)));

        var drained = counters.Drain();
        Assert.Equal(2, drained.Count);
        var main = drained.Single(item => item.Key.ClientId == "client");
        Assert.Equal(1_000, main.Count);
        Assert.Equal(day.AddSeconds(999), main.LastOccurredAtUtc);
        Assert.Equal(day.Date, main.Key.Day);
        Assert.Equal(1_001, runtime.Accepted);
        // Drained means started over.
        Assert.Empty(counters.Drain());
    }

    [Fact]
    public void Distinct_combinations_are_capped_without_blocking()
    {
        // A failed request names any client id it likes: memory must not follow it.
        var runtime = new IdentityMetricsRuntimeState();
        var counters = new IdentityUsageCounters(runtime);
        for (var index = 0; index < IdentityUsageCounters.MaximumKeys; index++)
            Assert.True(counters.TryRecord(Metric($"client-{index}")));

        Assert.False(counters.TryRecord(Metric("one-too-many")));
        // A known combination still counts.
        Assert.True(counters.TryRecord(Metric("client-0")));
        Assert.Equal(1, runtime.Dropped);
        Assert.Equal(IdentityUsageCounters.MaximumKeys, runtime.QueueDepth);
    }

    [Fact]
    public void Restored_counts_are_not_lost()
    {
        var counters = new IdentityUsageCounters(new IdentityMetricsRuntimeState());
        counters.TryRecord(Metric());
        var drained = counters.Drain();
        counters.TryRecord(Metric());
        counters.Restore(drained);
        Assert.Equal(2, counters.Drain().Single().Count);
    }

    /// <summary>
    /// Recording runs on the authentication path: it must never wait or touch
    /// I/O. Checked on the code, not with a stopwatch (see
    /// <c>TestSynchronizationContractTests</c>).
    /// </summary>
    [Fact]
    public void Recording_never_waits()
    {
        var source = File.ReadAllText(Path.Combine(
            RepositoryRoot(), "src", "sts", "Metrics", "IdentityUsageCounters.cs"));
        foreach (var forbidden in new[] { "await ", "Async(", ".Wait()", ".GetAwaiter().GetResult()", "lock (" })
            Assert.DoesNotContain(forbidden, source, StringComparison.Ordinal);
    }

    private static string RepositoryRoot([CallerFilePath] string sourceFile = "") =>
        Path.GetFullPath(Path.Combine(
            Path.GetDirectoryName(sourceFile)
                ?? throw new InvalidOperationException("Unable to resolve the test source directory."),
            "..",
            ".."));
}

/// <summary>The worker drains the counters into this node's rows of the daily aggregate.</summary>
public sealed class IdentityUsageMetricsWorkerTests
{
    [Fact]
    public async Task Each_node_adds_to_its_own_rows_and_a_failed_flush_loses_nothing()
    {
        var factory = Sufficit.Identity.Tests.Infrastructure.SufficitIdentityTestFactory.CreateIsolated(
            new Dictionary<string, string?>());
        await ((IAsyncLifetime)factory).InitializeAsync();
        try
        {
            var databases = factory.Services.GetRequiredService<IDbContextFactory<AppDbContext>>();
            var day = DateTime.UtcNow.Date.AddHours(1);

            async Task FlushAsync(string node, int uses)
            {
                var counters = new IdentityUsageCounters(new IdentityMetricsRuntimeState());
                for (var index = 0; index < uses; index++)
                    counters.TryRecord(new IdentityUsageMetric(day, "worker-client", "token_issued", "token", null, "succeeded"));
                var worker = Worker(factory, counters, node);
                await worker.FlushAsync(CancellationToken.None);
            }

            await FlushAsync("node-a", 3);
            await FlushAsync("node-a", 2);
            await FlushAsync("node-b", 4);

            await using (var database = await databases.CreateDbContextAsync())
            {
                var rows = await database.IdentityApplicationUsageDaily.AsNoTracking()
                    .Where(row => row.ClientId == "worker-client").OrderBy(row => row.Node).ToListAsync();
                Assert.Equal(2, rows.Count);
                Assert.Equal(("node-a", 5L), (rows[0].Node, rows[0].Count));
                Assert.Equal(("node-b", 4L), (rows[1].Node, rows[1].Count));
                Assert.All(rows, row => Assert.Equal(string.Empty, row.GrantType));
            }

            // Persisting fails (database gone): the counts go back to memory.
            var failing = new IdentityUsageCounters(new IdentityMetricsRuntimeState());
            failing.TryRecord(new IdentityUsageMetric(day, "worker-client", "token_issued", "token", null, "succeeded"));
            await using (var database = await databases.CreateDbContextAsync())
                await database.Database.ExecuteSqlRawAsync("DROP TABLE identityapplicationusagedaily");
            await Worker(factory, failing, "node-a").FlushAsync(CancellationToken.None);
            Assert.Equal(1, failing.Drain().Single().Count);
        }
        finally
        {
            factory.Dispose();
        }
    }

    private static IdentityUsageMetricsWorker Worker(
        Microsoft.AspNetCore.Mvc.Testing.WebApplicationFactory<Sufficit.Identity.Tests.Infrastructure.SufficitIdentityTestFactory> factory,
        IdentityUsageCounters counters, string node) => new(
            counters,
            factory.Services.GetRequiredService<IDbContextFactory<AppDbContext>>(),
            factory.Services.GetRequiredService<IHttpClientFactory>(),
            factory.Services.GetRequiredService<Sufficit.Identity.Vault.IKeyVault>(),
            new IdentityMetricsRuntimeState(),
            new ConfigurationBuilder().AddInMemoryCollection(new Dictionary<string, string?>
            {
                ["Sufficit:Identity:Metrics:NodeName"] = node,
            }).Build(),
            Microsoft.Extensions.Logging.Abstractions.NullLogger<IdentityUsageMetricsWorker>.Instance);
}

/// <summary>Who a use was for: a user when the token names one, nobody for a client acting as itself.</summary>
public sealed class IdentityUsageUserDimensionTests
{
    [Fact]
    public async Task Password_grant_counts_for_the_user_and_client_credentials_for_nobody()
    {
        var factory = Sufficit.Identity.Tests.Infrastructure.SufficitIdentityTestFactory.CreateIsolated(
            new Dictionary<string, string?>());
        await ((IAsyncLifetime)factory).InitializeAsync();
        try
        {
            var client = factory.CreateClient();
            var counters = factory.Services.GetRequiredService<IdentityUsageCounters>();
            counters.Drain();

            using (var cc = await client.PostAsync("/connect/token", new FormUrlEncodedContent(new Dictionary<string, string>
            {
                ["grant_type"] = "client_credentials",
                ["client_id"] = Sufficit.Identity.Tests.Infrastructure.TestDataSeeder.ClientCredentialsClientId,
                ["client_secret"] = Sufficit.Identity.Tests.Infrastructure.TestDataSeeder.ClientCredentialsClientSecret,
                ["scope"] = Sufficit.Identity.Tests.Infrastructure.TestDataSeeder.ScopeName,
            })))
                Assert.True(cc.IsSuccessStatusCode, await cc.Content.ReadAsStringAsync());
            using (var ropc = await client.PostAsync("/connect/token", new FormUrlEncodedContent(new Dictionary<string, string>
            {
                ["grant_type"] = "password",
                ["username"] = Sufficit.Identity.Tests.Infrastructure.TestDataSeeder.DefaultUsername,
                ["password"] = Sufficit.Identity.Tests.Infrastructure.TestDataSeeder.DefaultPassword,
                ["client_id"] = Sufficit.Identity.Tests.Infrastructure.TestDataSeeder.PasswordClientId,
                ["client_secret"] = Sufficit.Identity.Tests.Infrastructure.TestDataSeeder.PasswordClientSecret,
                ["scope"] = Sufficit.Identity.Tests.Infrastructure.TestDataSeeder.ScopeName,
            })))
                Assert.True(ropc.IsSuccessStatusCode, await ropc.Content.ReadAsStringAsync());

            await using var scope = factory.Services.CreateAsyncScope();
            var alice = await scope.ServiceProvider
                .GetRequiredService<Microsoft.AspNetCore.Identity.UserManager<Sufficit.Identity.Core.Entities.ApplicationUser>>()
                .FindByNameAsync(Sufficit.Identity.Tests.Infrastructure.TestDataSeeder.DefaultUsername);
            var drained = counters.Drain();
            Assert.Contains(drained, item => item.Key.ClientId == Sufficit.Identity.Tests.Infrastructure.TestDataSeeder.ClientCredentialsClientId
                && item.Key.UserId == string.Empty);
            Assert.Contains(drained, item => item.Key.ClientId == Sufficit.Identity.Tests.Infrastructure.TestDataSeeder.PasswordClientId
                && item.Key.UserId == alice!.Id);
        }
        finally
        {
            factory.Dispose();
        }
    }

    [Fact]
    public void The_export_never_carries_a_user()
    {
        var day = new DateTime(2026, 10, 22, 0, 0, 0, DateTimeKind.Utc);
        var key = new IdentityUsageKey(day, "app", "token_issued", "token", "password", "succeeded", "user-1");
        Assert.Equal(string.Empty, key.WithoutUser().UserId);
        var line = IdentityUsageMetricsWorker.BuildLineProtocol([(key.WithoutUser(), 3, day)], "node-a");
        Assert.DoesNotContain("user-1", line);
        Assert.Contains("value=3i", line);
    }

    [Fact]
    public void An_id_too_long_for_the_column_is_counted_without_a_user()
    {
        var metric = new IdentityUsageMetric(DateTime.UtcNow, "app", "token_issued", "token", null, "succeeded",
            new string('x', Sufficit.Identity.Core.Data.IdentityDatabaseSchema.MetricsUserIdLength + 1));
        Assert.Equal(string.Empty, IdentityUsageKey.From(metric).UserId);
    }
}
