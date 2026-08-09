using System.Net;
using Microsoft.Extensions.DependencyInjection;
using OpenIddict.Abstractions;
using Sufficit.Identity.STS;
using Sufficit.Identity.STS.Tokens;
using Sufficit.Identity.Tests.Infrastructure;
using Xunit;

namespace Sufficit.Identity.Tests;

public sealed class AccessTokenFormatPolicyTests
{
    [Fact]
    public void Resource_then_client_then_legacy_fallback_define_the_format()
    {
        var policy = new AccessTokenFormatPolicy(new TokenLifetimeOptions
        {
            UseReferenceAccessTokens = true,
            AccessTokenFormatsByClient = new(StringComparer.Ordinal)
            {
                ["jwt-client"] = AccessTokenStorageMode.Jwt,
            },
            AccessTokenFormatsByResource = new(StringComparer.Ordinal)
            {
                ["opaque-api"] = AccessTokenStorageMode.Reference,
            },
        });

        Assert.Equal(
            AccessTokenStorageMode.Reference,
            policy.Resolve("jwt-client", ["opaque-api"]).Format);
        Assert.Equal(
            AccessTokenStorageMode.Jwt,
            policy.Resolve("jwt-client", []).Format);
        Assert.Equal(
            AccessTokenStorageMode.Reference,
            policy.Resolve("legacy-client", []).Format);
    }

    [Fact]
    public void Conflicting_resource_formats_fail_closed()
    {
        var policy = new AccessTokenFormatPolicy(new TokenLifetimeOptions
        {
            AccessTokenFormatsByResource = new(StringComparer.Ordinal)
            {
                ["api-a"] = AccessTokenStorageMode.Jwt,
                ["api-b"] = AccessTokenStorageMode.Reference,
            },
        });

        var decision = policy.Resolve("client", ["api-a", "api-b"]);

        Assert.True(decision.HasConflict);
    }

    [Fact]
    public async Task Client_rule_migrates_one_client_to_jwt_without_a_flag_day()
    {
        using var factory = SufficitIdentityTestFactory.CreateIsolated(
            new Dictionary<string, string?>
            {
                [$"Sufficit:Identity:Tokens:AccessTokenFormatsByClient:{TestDataSeeder.ClientCredentialsClientId}"] =
                    "Jwt",
            });
        await ((IAsyncLifetime)factory).InitializeAsync();
        var client = factory.CreateClient();

        var (status, body) = await client.PostFormAsync(
            "/connect/token",
            new Dictionary<string, string>
            {
                ["grant_type"] = "client_credentials",
                ["client_id"] = TestDataSeeder.ClientCredentialsClientId,
                ["client_secret"] =
                    TestDataSeeder.ClientCredentialsClientSecret,
                ["scope"] = TestDataSeeder.ScopeName,
            });

        Assert.Equal(HttpStatusCode.OK, status);
        var token = body.GetProperty("access_token").GetString();
        Assert.False(string.IsNullOrWhiteSpace(token));
        Assert.Equal(3, token!.Split('.').Length);

        client.DefaultRequestHeaders.Authorization =
            IntrospectionTests.BasicAuthFor(
                TestDataSeeder.IntrospectionClientId,
                TestDataSeeder.IntrospectionClientSecret);
        var (introspectionStatus, introspection) = await client.PostFormAsync(
            "/connect/introspect",
            new Dictionary<string, string> { ["token"] = token! });
        Assert.Equal(HttpStatusCode.OK, introspectionStatus);
        Assert.True(introspection.GetProperty("active").GetBoolean());
    }
}
