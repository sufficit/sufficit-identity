using System.Net;
using System.Net.Http.Json;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Sufficit.Identity.Core.Data;
using Sufficit.Identity.Core.Entities;
using Sufficit.Identity.Management.Metrics;
using Sufficit.Identity.Tests.Infrastructure;
using Xunit;

namespace Sufficit.Identity.Tests;

public sealed class MetricsManagementTests
{
    [Fact]
    public void Aggregation_queries_translate_for_mariadb()
    {
        var options = new DbContextOptionsBuilder<AppDbContext>()
            .UseMySql(
                "server=localhost;database=identity_contract;user=contract",
                new MariaDbServerVersion(new Version(10, 4, 34)))
            .Options;
        using var database = new AppDbContext(options);
        var source = database.IdentityApplicationUsageEvents.AsNoTracking()
            .Where(item => item.OccurredAtUtc >= new DateTime(2026, 7, 1)
                && item.OccurredAtUtc < new DateTime(2026, 8, 1));

        var dailySql = MetricsManagementService
            .BuildDailyAggregationQuery(source)
            .ToQueryString();
        var grantsSql = MetricsManagementService
            .BuildGrantAggregationQuery(source)
            .ToQueryString();

        Assert.Contains("GROUP BY", dailySql, StringComparison.OrdinalIgnoreCase);
        Assert.Contains("year", dailySql, StringComparison.OrdinalIgnoreCase);
        Assert.Contains("month", dailySql, StringComparison.OrdinalIgnoreCase);
        Assert.Contains("day", dailySql, StringComparison.OrdinalIgnoreCase);
        Assert.Contains("GROUP BY", grantsSql, StringComparison.OrdinalIgnoreCase);
        Assert.Contains("granttype", grantsSql, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public async Task Overview_groups_events_by_utc_day()
    {
        using var factory = new ManagementTestFactory();
        await ((IAsyncLifetime)factory).InitializeAsync();
        await using (var scope = factory.Services.CreateAsyncScope())
        {
            var database = scope.ServiceProvider.GetRequiredService<AppDbContext>();
            database.IdentityApplicationUsageEvents.AddRange(
                UsageEvent(new DateTime(2026, 8, 10, 1, 15, 0, DateTimeKind.Utc)),
                UsageEvent(new DateTime(2026, 8, 10, 22, 45, 0, DateTimeKind.Utc)),
                UsageEvent(new DateTime(2026, 8, 11, 3, 30, 0, DateTimeKind.Utc)));
            await database.SaveChangesAsync();
        }

        using var response = await factory.CreateClient().GetAsync(
            "/api/metrics/overview?fromUtc=2026-08-10T00:00:00Z"
            + "&toUtc=2026-08-12T00:00:00Z");

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        var overview = await response.Content.ReadFromJsonAsync<ManagementMetricsOverview>();
        Assert.NotNull(overview);
        Assert.Equal(3, overview.TotalEvents);
        Assert.Collection(
            overview.Daily,
            first =>
            {
                Assert.Equal(new DateTime(2026, 8, 10), first.DateUtc.Date);
                Assert.Equal(2, first.Count);
            },
            second =>
            {
                Assert.Equal(new DateTime(2026, 8, 11), second.DateUtc.Date);
                Assert.Equal(1, second.Count);
            });
    }

    private static IdentityApplicationUsageEvent UsageEvent(DateTime occurredAtUtc) => new()
    {
        OccurredAtUtc = occurredAtUtc,
        ClientId = "metrics-test-client",
        EventType = "token_issued",
        EndpointType = "token",
        GrantType = "client_credentials",
        Outcome = "succeeded",
    };
}
