using System.Text.Json;
using Microsoft.AspNetCore.Http;
using Sufficit.Identity.Server;
using Xunit;

namespace Sufficit.Identity.Tests;

public sealed class IdentityRateLimitPolicyTests
{
    [Fact]
    public void Par_and_token_requests_use_independent_partitions()
    {
        const string clientIp = "192.0.2.10";

        var par = IdentityRateLimitPolicy.GetCredentialPartitionKey(
            "/connect/par",
            HttpMethods.Post,
            clientIp);
        var token = IdentityRateLimitPolicy.GetCredentialPartitionKey(
            "/connect/token",
            HttpMethods.Post,
            clientIp);

        Assert.Equal("par-ip:192.0.2.10", par);
        Assert.Equal("credential-ip:192.0.2.10", token);
        Assert.NotEqual(par, token);
    }

    /// <summary>
    /// The management API and SCIM were entirely unthrottled — the limiter
    /// covered <c>/connect/*</c> and <c>/account/*</c> only (eval 2026-08-23,
    /// S-10), so a caller holding a valid operator token could drive unbounded
    /// database work through them.
    /// </summary>
    [Theory]
    [InlineData("/api/users")]
    [InlineData("/api/clients/abc/credentials")]
    [InlineData("/scim/v2/users")]
    public void Administrative_surfaces_are_throttled(string path)
    {
        Assert.True(
            IdentityRateLimitPolicy.IsAdministrativeEndpoint(path, "api"));
    }

    [Theory]
    [InlineData("/connect/token")]
    [InlineData("/account/login/password")]
    [InlineData("/health")]
    public void Non_administrative_paths_keep_their_own_buckets(string path)
    {
        Assert.False(
            IdentityRateLimitPolicy.IsAdministrativeEndpoint(path, "api"));
    }

    /// <summary>
    /// A deployment that moves the management API off the default prefix must
    /// not silently become unthrottled again.
    /// </summary>
    [Fact]
    public void Administrative_detection_follows_the_configured_prefix()
    {
        Assert.True(IdentityRateLimitPolicy.IsAdministrativeEndpoint(
            "/management/users",
            "management"));
        Assert.False(IdentityRateLimitPolicy.IsAdministrativeEndpoint(
            "/api/users",
            "management"));
    }

    /// <summary>
    /// Bulk commands carry the opposite cost profile from ordinary calls — one
    /// request, a great deal of server work. They need a separate bucket so a
    /// provisioning run and everyday traffic cannot exhaust each other's
    /// budget and produce a 429 caused by unrelated legitimate work.
    /// </summary>
    [Theory]
    [InlineData("/api/provisioning/manifest/apply")]
    [InlineData("/api/provisioning/manifest/preview")]
    [InlineData("/api/provisioning/token")]
    [InlineData("/api/sessions/users/user-1")]
    public void Bulk_commands_get_their_own_partition(string path)
    {
        Assert.True(IdentityRateLimitPolicy.IsBulkEndpoint(path, "api"));

        var bulk = IdentityRateLimitPolicy.GetAdministrativePartitionKey(
            path,
            "api",
            "192.0.2.10");
        var ordinary = IdentityRateLimitPolicy.GetAdministrativePartitionKey(
            "/api/users",
            "api",
            "192.0.2.10");

        Assert.StartsWith("admin-bulk-ip:", bulk, StringComparison.Ordinal);
        Assert.StartsWith("admin-ip:", ordinary, StringComparison.Ordinal);
        Assert.NotEqual(bulk, ordinary);
    }

    [Theory]
    [InlineData("/api/users")]
    [InlineData("/api/clients")]
    [InlineData("/scim/v2/groups")]
    public void Ordinary_administrative_calls_are_not_treated_as_bulk(string path)
    {
        Assert.False(IdentityRateLimitPolicy.IsBulkEndpoint(path, "api"));
    }

    [Fact]
    public async Task Par_rate_limit_response_is_rfc_compliant_oauth_json()
    {
        var context = new DefaultHttpContext();
        context.Request.Method = HttpMethods.Post;
        context.Request.Path = "/connect/par";
        context.Response.Body = new MemoryStream();

        await IdentityRateLimitPolicy.WriteRejectionResponseAsync(
            context,
            retryAfterSeconds: 60,
            CancellationToken.None);

        Assert.Equal(StatusCodes.Status429TooManyRequests, context.Response.StatusCode);
        Assert.Equal("60", context.Response.Headers.RetryAfter);
        Assert.Equal("no-store", context.Response.Headers.CacheControl);
        Assert.Equal("no-cache", context.Response.Headers.Pragma);
        Assert.Equal("application/json", context.Response.ContentType?.Split(';')[0]);

        context.Response.Body.Position = 0;
        using var payload = await JsonDocument.ParseAsync(context.Response.Body);
        Assert.Equal(
            "temporarily_unavailable",
            payload.RootElement.GetProperty("error").GetString());
    }
}
