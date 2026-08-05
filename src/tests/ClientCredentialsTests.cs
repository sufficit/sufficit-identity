using System.Net;
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
}
