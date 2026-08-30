using System.Net;
using System.Threading.RateLimiting;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.RateLimiting;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;
using Sufficit.Identity.Server;
using Sufficit.Identity.STS;
using Xunit;

namespace Sufficit.Identity.Tests;

/// <summary>
/// Drives the real production limiter assembled by
/// <c>AddSufficitIdentityRateLimiter</c> — the same method
/// <c>src/server/Program.cs</c> calls — through a
/// <see cref="DefaultHttpContext"/>, so the credential/admin/PAR/device
/// partitioning is under test without coupling the whole integration suite to a
/// process-wide singleton limiter (eval 2026-08-30, architecture item 1).
/// </summary>
public sealed class RateLimiterServiceCollectionExtensionsTests
{
    private static PartitionedRateLimiter<HttpContext> BuildLimiter(
        RateLimitOptions rateLimit,
        string managementRoutePrefix = "api")
    {
        var services = new ServiceCollection();
        services.AddLogging();
        services.AddSufficitIdentityRateLimiter(rateLimit, managementRoutePrefix);
        var provider = services.BuildServiceProvider();
        var options = provider.GetRequiredService<IOptions<RateLimiterOptions>>().Value;
        return options.GlobalLimiter
            ?? throw new InvalidOperationException("No global limiter registered.");
    }

    private static DefaultHttpContext Request(string method, string path, string ip)
    {
        var context = new DefaultHttpContext();
        context.Request.Method = method;
        context.Request.Path = path;
        context.Connection.RemoteIpAddress = IPAddress.Parse(ip);
        return context;
    }

    private static int AcquireUntilRejected(
        PartitionedRateLimiter<HttpContext> limiter,
        HttpContext context,
        int ceiling)
    {
        var granted = 0;
        for (var attempt = 0; attempt < ceiling; attempt++)
        {
            using var lease = limiter.AttemptAcquire(context);
            if (!lease.IsAcquired)
            {
                break;
            }

            granted++;
        }

        return granted;
    }

    [Fact]
    public void Credential_endpoint_is_throttled_at_the_configured_permit_limit()
    {
        var limiter = BuildLimiter(new RateLimitOptions { PermitLimit = 3 });
        var context = Request(HttpMethods.Post, "/connect/token", "192.0.2.1");

        // The 4th attempt in the window is rejected.
        Assert.Equal(3, AcquireUntilRejected(limiter, context, ceiling: 10));
        using var overflow = limiter.AttemptAcquire(context);
        Assert.False(overflow.IsAcquired);
    }

    [Fact]
    public void Different_source_ips_do_not_share_a_credential_bucket()
    {
        var limiter = BuildLimiter(new RateLimitOptions { PermitLimit = 2 });

        Assert.Equal(2, AcquireUntilRejected(
            limiter, Request(HttpMethods.Post, "/connect/token", "192.0.2.1"), 10));
        // A second address starts with a full budget of its own.
        Assert.Equal(2, AcquireUntilRejected(
            limiter, Request(HttpMethods.Post, "/connect/token", "192.0.2.2"), 10));
    }

    [Fact]
    public void Par_credential_and_admin_buckets_are_independent()
    {
        var limiter = BuildLimiter(new RateLimitOptions
        {
            PermitLimit = 1,
            PushedAuthorizationPermitLimit = 1,
            AdministrativePermitLimit = 1,
        });
        const string ip = "192.0.2.5";

        // Each classification exhausts its own single permit without touching
        // the others'.
        Assert.True(limiter.AttemptAcquire(
            Request(HttpMethods.Post, "/connect/token", ip)).IsAcquired);
        Assert.True(limiter.AttemptAcquire(
            Request(HttpMethods.Post, "/connect/par", ip)).IsAcquired);
        Assert.True(limiter.AttemptAcquire(
            Request(HttpMethods.Post, "/api/users", ip)).IsAcquired);

        // ...and each is now independently exhausted.
        Assert.False(limiter.AttemptAcquire(
            Request(HttpMethods.Post, "/connect/token", ip)).IsAcquired);
        Assert.False(limiter.AttemptAcquire(
            Request(HttpMethods.Post, "/connect/par", ip)).IsAcquired);
        Assert.False(limiter.AttemptAcquire(
            Request(HttpMethods.Post, "/api/users", ip)).IsAcquired);
    }

    [Fact]
    public void Bulk_and_ordinary_admin_calls_do_not_starve_each_other()
    {
        var limiter = BuildLimiter(new RateLimitOptions
        {
            AdministrativePermitLimit = 1,
            AdministrativeBulkPermitLimit = 1,
        });
        const string ip = "192.0.2.6";

        Assert.True(limiter.AttemptAcquire(
            Request(HttpMethods.Post, "/api/provisioning/manifest/apply", ip)).IsAcquired);
        // An ordinary admin call still has its own budget after the bulk one.
        Assert.True(limiter.AttemptAcquire(
            Request(HttpMethods.Post, "/api/users", ip)).IsAcquired);
        // Each is then independently exhausted.
        Assert.False(limiter.AttemptAcquire(
            Request(HttpMethods.Post, "/api/provisioning/manifest/apply", ip)).IsAcquired);
        Assert.False(limiter.AttemptAcquire(
            Request(HttpMethods.Post, "/api/users", ip)).IsAcquired);
    }

    [Fact]
    public void Unclassified_requests_are_not_limited()
    {
        var limiter = BuildLimiter(new RateLimitOptions { PermitLimit = 1 });
        var context = Request(HttpMethods.Get, "/.well-known/openid-configuration", "192.0.2.7");

        // Well past any configured limit — a discovery GET is never throttled.
        for (var attempt = 0; attempt < 50; attempt++)
        {
            using var lease = limiter.AttemptAcquire(context);
            Assert.True(lease.IsAcquired);
        }
    }
}
