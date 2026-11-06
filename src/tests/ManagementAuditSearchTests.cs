using System.Net;
using System.Net.Http.Json;
using System.Security.Claims;
using Microsoft.AspNetCore.Hosting;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Sufficit.Identity.Core.Data;
using Sufficit.Identity.Core.Entities;
using Sufficit.Identity.Management.Audit;
using Sufficit.Identity.Management.Authorization;
using Sufficit.Identity.Tests.Infrastructure;
using Xunit;

namespace Sufficit.Identity.Tests;

public sealed class ManagementAuditSearchTests
{
    [Fact]
    public async Task Search_exposes_a_bounded_page_without_caching()
    {
        using var factory = new ManagementTestFactory();
        await ((IAsyncLifetime)factory).InitializeAsync();
        await using var scope = factory.Services.CreateAsyncScope();
        var database = scope.ServiceProvider.GetRequiredService<AppDbContext>();
        database.ManagementAuditEvents.AddRange(Enumerable.Range(0, 260)
            .Select(_ => Entry(DateTime.UtcNow, "user", "target")));
        await database.SaveChangesAsync();
        using var client = factory.CreateClient();
        using var response = await client.PostAsJsonAsync("/api/audit/search", new { limit = int.MaxValue });
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        Assert.True(response.Headers.CacheControl?.NoStore);
        var page = await response.Content.ReadFromJsonAsync<ManagementAuditPage>();
        Assert.Equal(250, page!.Items.Count);
        Assert.NotNull(page.NextCursor);
        var minimum = await client.PostAsJsonAsync("/api/audit/search", new { limit = 0 });
        Assert.Single((await minimum.Content.ReadFromJsonAsync<ManagementAuditPage>())!.Items);
        using var legacy = await client.GetAsync("/api/audit?limit=10");
        Assert.Equal(10, (await legacy.Content.ReadFromJsonAsync<ManagementAuditRecord[]>())!.Length);
        Assert.True(legacy.Headers.CacheControl?.NoStore);
    }

    [Fact]
    public async Task Search_reaches_older_account_events_and_pages_timestamp_ties_without_duplicates()
    {
        using var factory = new ManagementTestFactory();
        await ((IAsyncLifetime)factory).InitializeAsync();
        await using var scope = factory.Services.CreateAsyncScope();
        var database = scope.ServiceProvider.GetRequiredService<AppDbContext>();
        var start = new DateTime(2026, 11, 5, 3, 0, 0, DateTimeKind.Utc);
        var end = start.AddDays(1);
        var matching = Enumerable.Range(0, 4).Select(i => Entry(i == 3 ? start.AddHours(1) : start, "user", "target")).ToArray();
        database.ManagementAuditEvents.AddRange(matching);
        database.ManagementAuditEvents.AddRange(
            Entry(start.AddTicks(-1), "user", "target"),
            Entry(end, "user", "target"),
            Entry(start, "client", "target"),
            Entry(start, "user", "other"));
        database.ManagementAuditEvents.AddRange(Enumerable.Range(0, 260)
            .Select(_ => Entry(end.AddDays(1), "user", "other")));
        await database.SaveChangesAsync();
        using var client = factory.CreateClient();
        var query = new ManagementAuditQuery("user", "target",
            new DateTimeOffset(2026, 11, 5, 0, 0, 0, TimeSpan.FromHours(-3)),
            new DateTimeOffset(end), Limit: 2);
        using var firstResponse = await client.PostAsJsonAsync("/api/audit/search", query);
        Assert.Equal(HttpStatusCode.OK, firstResponse.StatusCode);
        var first = (await firstResponse.Content.ReadFromJsonAsync<ManagementAuditPage>())!;
        Assert.Equal(matching.Reverse().Take(2).Select(x => x.Id), first.Items.Select(x => x.Id));
        Assert.NotNull(first.NextCursor);
        // A concurrent insert at the same timestamp must not shift page two.
        database.ManagementAuditEvents.Add(Entry(start, "user", "target"));
        await database.SaveChangesAsync();
        using var secondResponse = await client.PostAsJsonAsync("/api/audit/search", query with { Cursor = first.NextCursor });
        var second = (await secondResponse.Content.ReadFromJsonAsync<ManagementAuditPage>())!;
        Assert.Equal(matching.Reverse().Skip(2).Select(x => x.Id), second.Items.Select(x => x.Id));
        Assert.Null(second.NextCursor);
        Assert.Empty(first.Items.Select(x => x.Id).Intersect(second.Items.Select(x => x.Id)));
    }

    [Theory]
    [InlineData("")]
    [InlineData("garbage")]
    [InlineData("3155378976000000000:1")]
    [InlineData("638000000000000000:0")]
    [InlineData("-1:1")]
    [InlineData("638000000000000000:1:2")]
    public async Task Search_rejects_malformed_cursors(string cursor)
    {
        using var factory = new ManagementTestFactory();
        await ((IAsyncLifetime)factory).InitializeAsync();
        using var client = factory.CreateClient();
        using var response = await client.PostAsJsonAsync("/api/audit/search", new { cursor });
        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
        Assert.Contains("audit_cursor_invalid", await response.Content.ReadAsStringAsync());
    }

    [Fact]
    public async Task Search_rejects_invalid_interval_and_oversized_filters()
    {
        using var factory = new ManagementTestFactory();
        await ((IAsyncLifetime)factory).InitializeAsync();
        using var client = factory.CreateClient();
        var now = DateTimeOffset.UtcNow;
        foreach (var query in new[]
        {
            new ManagementAuditQuery(FromUtc: now, ToUtc: now),
            new ManagementAuditQuery(FromUtc: now, ToUtc: now.AddSeconds(-1)),
            new ManagementAuditQuery(ResourceId: new string('x', 256)),
            new ManagementAuditQuery(ResourceType: new string('x', 101)),
            new ManagementAuditQuery(Cursor: new string('1', 41)),
        })
        {
            using var response = await client.PostAsJsonAsync("/api/audit/search", query);
            Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
        }
    }

    [Fact]
    public async Task Search_requires_audit_read_even_with_valid_cursor()
    {
        using var factory = new ManagementTestFactory();
        await ((IAsyncLifetime)factory).InitializeAsync();
        using var deniedFactory = factory.WithWebHostBuilder(builder => builder.ConfigureServices(services =>
        {
            services.RemoveAll<IManagementAuthorizationEvaluator>();
            services.AddSingleton<IManagementAuthorizationEvaluator, DenyAudit>();
        }));
        using var client = deniedFactory.CreateClient();
        using var response = await client.PostAsJsonAsync("/api/audit/search",
            new ManagementAuditQuery(Cursor: "638000000000000000:1"));
        Assert.Equal(HttpStatusCode.Forbidden, response.StatusCode);
        using var legacy = await client.GetAsync("/api/audit");
        Assert.Equal(HttpStatusCode.Forbidden, legacy.StatusCode);
    }

    [Fact]
    public async Task Search_rejects_unauthenticated_requests_at_http_boundary()
    {
        using var factory = ManagementTestFactory.CreateWithRealAuthz();
        await ((IAsyncLifetime)factory).InitializeAsync();
        using var client = factory.CreateClient();
        using var response = await client.PostAsJsonAsync("/api/audit/search", new { limit = 10 });
        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
    }

    private static ManagementAuditEvent Entry(DateTime time, string type, string id) => new()
    {
        OccurredAtUtc = time,
        OperatorSubject = "operator-test",
        Capability = ManagementCapabilities.UsersUpdate,
        ResourceType = type,
        ResourceId = id,
        AuthorizationOutcome = "allowed",
        OperationOutcome = "succeeded",
        ReasonCode = "user_profile_updated",
        CorrelationId = "audit-search-test",
    };

    private sealed class DenyAudit : IManagementAuthorizationEvaluator
    {
        public ValueTask<ManagementAuthorizationDecision> EvaluateAsync(
            ClaimsPrincipal principal, string capability, ManagementResource resource,
            CancellationToken cancellationToken = default)
        {
            Assert.Equal(ManagementCapabilities.AuditRead, capability);
            return ValueTask.FromResult(ManagementAuthorizationDecision.Denied("capability_not_granted"));
        }
    }
}
