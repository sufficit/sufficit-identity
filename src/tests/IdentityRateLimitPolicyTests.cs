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
