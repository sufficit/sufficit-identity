using System.Net;
using System.Net.Http.Json;
using System.Security.Claims;
using Microsoft.AspNetCore.Http;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;
using Sufficit.Identity.Core.Data;
using Sufficit.Identity.Core.Networking;
using Sufficit.Identity.Management.Authorization;
using Sufficit.Identity.Management.Networking;
using Sufficit.Identity.Server;
using Sufficit.Identity.Tests.Infrastructure;
using Xunit;

namespace Sufficit.Identity.Tests;

public sealed class TrustedProxyTests
{
    private static ManagementTestFactory Factory() => new(extraConfiguration: new Dictionary<string, string?>
    {
        ["Sufficit:Identity:TrustedProxies:0"] = "127.0.0.1/32",
        ["Sufficit:Identity:TrustedProxies:1"] = "172.16.2.0/32",
    });

    [Theory]
    [InlineData("0.0.0.0/0")]
    [InlineData("::/0")]
    [InlineData("example.com")]
    [InlineData("192.0.2.1/99")]
    [InlineData("fe80::1%eth0")]
    public void Invalid_or_unbounded_networks_are_rejected(string network) =>
        Assert.Throws<ArgumentException>(() => TrustedProxyValidation.Normalize([network]));

    [Fact]
    public void IPv4_and_IPv6_addresses_are_canonical_and_deduplicated()
    {
        var result = TrustedProxyValidation.Normalize([" 192.0.2.7 ", "192.0.2.7/32", "2001:db8::1", "::ffff:192.0.2.7"]);
        Assert.Equal(["192.0.2.7/32", "2001:db8::1/128"], result.ToArray());
        Assert.Equal("172.16.2.0/24", TrustedProxyValidation.Normalize(["172.16.2.1/24"])[0]);
    }

    [Theory]
    [InlineData(null, "198.51.100.7, 172.16.2.0", "198.51.100.7")]
    [InlineData("127.0.0.1", "198.51.100.7, 172.16.2.0", "198.51.100.7")]
    [InlineData("127.0.0.1", "203.0.113.8, 198.51.100.7, 172.16.2.0", "198.51.100.7")]
    [InlineData("127.0.0.1", "198.51.100.7, 192.0.2.20", "192.0.2.20")]
    [InlineData("192.0.2.20", "198.51.100.7, 172.16.2.0", "192.0.2.20")]
    [InlineData("::ffff:127.0.0.1", "2001:db8::10, 172.16.2.0", "2001:db8::10")]
    public async Task Forwarding_honors_two_hops_and_stops_at_untrusted_peers(string? peer, string header, string expected)
    {
        using var factory = Factory();
        var snapshots = factory.Services.GetRequiredService<TrustedProxySnapshotStore>();
        await snapshots.RefreshAsync();
        var middleware = new TrustedProxyForwardingMiddleware(_ => Task.CompletedTask, snapshots, NullLoggerFactory.Instance);
        var request = Request(peer, header);
        await middleware.InvokeAsync(request);
        Assert.Equal(expected, request.Connection.RemoteIpAddress!.ToString());
    }

    [Fact]
    public async Task Save_merges_with_files_audits_before_after_and_updates_memory()
    {
        using var factory = Factory();
        using var client = factory.CreateClient();
        var original = await client.GetFromJsonAsync<ManagementTrustedProxies>("/api/trusted-proxies");
        var response = await client.PutAsJsonAsync("/api/trusted-proxies",
            new SaveTrustedProxies(["192.0.2.7", "172.16.2.0/32"], 3, original!.Revision));
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        var saved = (await response.Content.ReadFromJsonAsync<ManagementTrustedProxies>())!;
        Assert.Equal(3, saved.ForwardLimit);
        Assert.Equal(3, saved.EffectiveNetworks.Count);
        Assert.Contains("127.0.0.1/32", saved.FileNetworks);
        Assert.Contains("192.0.2.7/32", saved.DatabaseNetworks);
        Assert.NotEqual(original.Revision, saved.Revision);
        Assert.Equal(saved.Revision, factory.Services.GetRequiredService<TrustedProxySnapshotStore>().Current.Revision);
        await using var scope = factory.Services.CreateAsyncScope();
        var database = scope.ServiceProvider.GetRequiredService<AppDbContext>();
        var audit = await database.ManagementAuditEvents.SingleAsync(x => x.Capability == ManagementCapabilities.TrustedProxiesManage);
        Assert.Equal("succeeded", audit.OperationOutcome);
        Assert.Contains("\"Networks\":[]", audit.BeforeJson);
        Assert.Contains("192.0.2.7/32", audit.AfterJson);
        Assert.False(string.IsNullOrWhiteSpace(audit.CorrelationId));

        var clear = await client.PutAsJsonAsync("/api/trusted-proxies", new SaveTrustedProxies([], null, saved.Revision));
        var cleared = (await clear.Content.ReadFromJsonAsync<ManagementTrustedProxies>())!;
        Assert.Equal(2, cleared.ForwardLimit);
        Assert.Equal(original.FileNetworks, cleared.EffectiveNetworks);
    }

    [Fact]
    public async Task Stale_revision_cannot_overwrite_another_operators_change()
    {
        using var factory = Factory();
        using var client = factory.CreateClient();
        var original = (await client.GetFromJsonAsync<ManagementTrustedProxies>("/api/trusted-proxies"))!;
        (await client.PutAsJsonAsync("/api/trusted-proxies", new SaveTrustedProxies(["192.0.2.1"], null, original.Revision))).EnsureSuccessStatusCode();
        var stale = await client.PutAsJsonAsync("/api/trusted-proxies", new SaveTrustedProxies(["192.0.2.2"], null, original.Revision));
        Assert.Equal(HttpStatusCode.BadRequest, stale.StatusCode);
        Assert.Contains("trusted_proxy_conflict", await stale.Content.ReadAsStringAsync());
        var current = (await client.GetFromJsonAsync<ManagementTrustedProxies>("/api/trusted-proxies"))!;
        Assert.Equal(["192.0.2.1/32"], current.DatabaseNetworks);
    }

    [Fact]
    public async Task Audit_failure_rolls_back_configuration_and_leaves_snapshot_unchanged()
    {
        using var factory = Factory();
        await using var scope = factory.Services.CreateAsyncScope();
        var service = scope.ServiceProvider.GetRequiredService<ITrustedProxyManagementService>();
        var context = new ManagementRequestContext(new ClaimsPrincipal(), "rollback-test");
        var original = await service.GetAsync(context);
        var database = scope.ServiceProvider.GetRequiredService<AppDbContext>();
        await database.Database.ExecuteSqlRawAsync("CREATE TRIGGER reject_proxy_audit BEFORE INSERT ON managementauditevents BEGIN SELECT RAISE(ABORT, 'audit unavailable'); END;");
        await Assert.ThrowsAsync<DbUpdateException>(() => service.SaveAsync(new(["192.0.2.8"], 3, original.Revision), context));
        database.ChangeTracker.Clear();
        Assert.Equal(original.Revision, (await database.TrustedProxyConfigurations.SingleAsync()).Revision);
        Assert.Equal(original.Revision, factory.Services.GetRequiredService<TrustedProxySnapshotStore>().Current.Revision);
    }

    [Fact]
    public async Task Another_instance_refreshes_and_forwarding_never_queries_database()
    {
        using var factory = Factory();
        var other = new TrustedProxySnapshotStore(factory.Services.GetRequiredService<IServiceScopeFactory>(),
            factory.Services.GetRequiredService<IOptions<TrustedProxyOptions>>(), NullLogger<TrustedProxySnapshotStore>.Instance);
        await other.RefreshAsync();
        var middleware = new TrustedProxyForwardingMiddleware(_ => Task.CompletedTask, other, NullLoggerFactory.Instance);
        using var client = factory.CreateClient();
        var baseline = other.Current;
        var beforeTrust = Request("127.0.0.1", "198.51.100.9, 192.0.2.20");
        await middleware.InvokeAsync(beforeTrust);
        Assert.Equal("192.0.2.20", beforeTrust.Connection.RemoteIpAddress!.ToString());
        (await client.PutAsJsonAsync("/api/trusted-proxies", new SaveTrustedProxies(["192.0.2.20"], null, baseline.Revision))).EnsureSuccessStatusCode();
        Assert.Same(baseline, other.Current);
        await other.RefreshAsync();
        Assert.NotSame(baseline, other.Current);
        await using var scope = factory.Services.CreateAsyncScope();
        var database = scope.ServiceProvider.GetRequiredService<AppDbContext>();
        await database.Database.ExecuteSqlRawAsync("DROP TABLE trustedproxyconfiguration");
        for (var i = 0; i < 20; i++)
        {
            var request = Request("127.0.0.1", "198.51.100.9, 192.0.2.20");
            await middleware.InvokeAsync(request);
            Assert.Equal("198.51.100.9", request.Connection.RemoteIpAddress!.ToString());
        }
        var valid = other.Current;
        await Assert.ThrowsAnyAsync<Exception>(() => other.RefreshAsync());
        Assert.Same(valid, other.Current);
    }

    [Fact]
    public async Task Anonymous_HTTP_and_direct_service_calls_are_denied()
    {
        using var factory = ManagementTestFactory.CreateWithRealAuthz();
        using var client = factory.CreateClient();
        var response = await client.GetAsync("/api/trusted-proxies");
        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
        await using var scope = factory.Services.CreateAsyncScope();
        var service = scope.ServiceProvider.GetRequiredService<ITrustedProxyManagementService>();
        var context = new ManagementRequestContext(new ClaimsPrincipal(), "unauthorized-test");
        await Assert.ThrowsAsync<ManagementAccessException>(() => service.GetAsync(context));
        await Assert.ThrowsAsync<ManagementAccessException>(() => service.SaveAsync(new([], null, "initial"), context));
    }

    [Fact]
    public async Task Read_only_operator_cannot_write_and_writer_requires_MFA()
    {
        using var factory = new ManagementTestFactory(bypassAuthz: false,
            extraConfiguration: new Dictionary<string, string?>
            {
                ["Sufficit:Identity:Management:RequireMfa"] = "true",
            });
        await using var scope = factory.Services.CreateAsyncScope();
        var service = scope.ServiceProvider.GetRequiredService<ITrustedProxyManagementService>();
        static ClaimsPrincipal Operator(string capability, bool mfa) => new(new ClaimsIdentity(
            new[] { new Claim("sub", "proxy-admin"), new Claim("permission", capability) }
                .Concat(mfa ? [new Claim("amr", "mfa")] : []), "test"));
        var reader = new ManagementRequestContext(Operator(ManagementCapabilities.TrustedProxiesRead, true), "read-only");
        var original = await service.GetAsync(reader);
        await Assert.ThrowsAsync<ManagementAccessException>(() => service.SaveAsync(new([], 3, original.Revision), reader));
        var writer = new ManagementRequestContext(Operator(ManagementCapabilities.TrustedProxiesManage, false), "mfa-required");
        var missingMfa = await Assert.ThrowsAsync<ManagementAccessException>(() => service.SaveAsync(new([], 3, original.Revision), writer));
        Assert.Equal(ManagementAuthorizationOutcome.StepUpRequired, missingMfa.Decision.Outcome);
        var approved = writer with { Operator = Operator(ManagementCapabilities.TrustedProxiesManage, true) };
        await service.SaveAsync(new([], 3, original.Revision), approved);
        var database = scope.ServiceProvider.GetRequiredService<AppDbContext>();
        var audit = await database.ManagementAuditEvents.SingleAsync(x => x.OperationOutcome == "succeeded");
        Assert.Equal("proxy-admin", audit.OperatorSubject);
        Assert.Contains("mfa", audit.AuthenticationMethods);
    }

    private static DefaultHttpContext Request(string? peer, string header)
    {
        var context = new DefaultHttpContext();
        context.Connection.RemoteIpAddress = peer is null ? null : IPAddress.Parse(peer);
        context.Request.Headers["X-Forwarded-For"] = header;
        context.Request.Headers["X-Forwarded-Proto"] = "https";
        return context;
    }
}
