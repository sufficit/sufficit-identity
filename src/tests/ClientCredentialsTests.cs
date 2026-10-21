using System.Net;
using System.Net.Http.Headers;
using Sufficit.Identity.Tests.Infrastructure;
using Xunit;

namespace Sufficit.Identity.Tests;

[Collection(StsCollection.Name)]
public sealed class ClientCredentialsTests
{
    private readonly SufficitIdentityTestFactory _factory;

    public ClientCredentialsTests(SufficitIdentityTestFactory factory) => _factory = factory;

    [Fact]
    public async Task Client_credentials_grant_issues_a_bearer_access_token()
    {
        var client = _factory.CreateClient();

        var (status, body) = await client.PostFormAsync("/connect/token", new Dictionary<string, string>
        {
            ["grant_type"] = "client_credentials",
            ["client_id"] = TestDataSeeder.ClientCredentialsClientId,
            ["client_secret"] = TestDataSeeder.ClientCredentialsClientSecret,
            ["scope"] = TestDataSeeder.ScopeName,
        });

        Assert.Equal(HttpStatusCode.OK, status);
        Assert.Equal("Bearer", body.GetProperty("token_type").GetString());

        // Reference access tokens (UseReferenceAccessTokens) are opaque; only
        // non-emptiness is asserted here, not any particular JWT-like shape.
        var accessToken = body.GetProperty("access_token").GetString();
        Assert.False(string.IsNullOrEmpty(accessToken));
    }

    // A client token has no user behind it. UserInfo threw "The user details
    // cannot be retrieved" (HTTP 500) for it — ~4,600 times a day in
    // production from a polling client — instead of answering invalid_token.
    [Fact]
    public async Task UserInfo_rejects_a_client_token_with_invalid_token_not_a_server_error()
    {
        var client = _factory.CreateClient();
        var (_, body) = await client.PostFormAsync("/connect/token", new Dictionary<string, string>
        {
            ["grant_type"] = "client_credentials",
            ["client_id"] = TestDataSeeder.ClientCredentialsClientId,
            ["client_secret"] = TestDataSeeder.ClientCredentialsClientSecret,
            ["scope"] = TestDataSeeder.ScopeName,
        });
        using var request = new HttpRequestMessage(HttpMethod.Get, "/connect/userinfo");
        request.Headers.Authorization = new AuthenticationHeaderValue(
            "Bearer", body.GetProperty("access_token").GetString());

        using var response = await client.SendAsync(request);

        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
        Assert.Contains(
            response.Headers.WwwAuthenticate,
            header => header.Parameter?.Contains("invalid_token", StringComparison.Ordinal) == true);
    }
}
