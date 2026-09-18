using System.Net;
using System.Net.Http.Json;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text.Json;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Tokens;
using OpenIddict.Abstractions;
using Sufficit.Identity.Management.Controllers;
using Sufficit.Identity.Tests.Infrastructure;
using Xunit;
using static OpenIddict.Abstractions.OpenIddictConstants;

namespace Sufficit.Identity.Tests;

/// <summary>
/// RFC 7523 defines no media type for a client assertion, and client libraries
/// sign it with the ordinary <c>typ: JWT</c>. OpenIddict accepts only its own
/// <c>client-authentication+jwt</c>, which answered every standard client with
/// invalid_client — the FAPI 2 conformance plan could not make its first
/// request. See STS/ClientAuthentication/StandardClientAssertionType.cs.
/// </summary>
public sealed class StandardClientAssertionTests
{
    [Theory]
    [InlineData(JwtConstants.HeaderType)]
    [InlineData(JsonWebTokenTypes.ClientAuthentication)]
    public async Task Client_assertion_is_accepted_with_a_standard_type(string tokenType)
    {
        var (factory, client, clientId, key) = await CreateClientAsync();
        using var _ = factory;

        var (status, body) = await client.PostFormAsync(
            "/connect/token",
            TokenRequest(clientId, CreateAssertion(clientId, key, tokenType, clientId)));

        Assert.Equal(HttpStatusCode.OK, status);
        Assert.False(string.IsNullOrWhiteSpace(
            body.GetProperty("access_token").GetString()));
    }

    [Fact]
    public async Task A_token_typed_for_another_purpose_is_still_rejected()
    {
        var (factory, client, clientId, key) = await CreateClientAsync();
        using var _ = factory;

        var (status, body) = await client.PostFormAsync(
            "/connect/token",
            TokenRequest(clientId, CreateAssertion(clientId, key, "at+jwt", clientId)));

        Assert.NotEqual(HttpStatusCode.OK, status);
        Assert.Equal(Errors.InvalidClient, body.GetProperty("error").GetString());
    }

    [Fact]
    public async Task An_assertion_that_is_not_self_issued_is_still_rejected()
    {
        var (factory, client, clientId, key) = await CreateClientAsync();
        using var _ = factory;

        // Same key, same issuer, but a subject that is not the client: the
        // shape of a request object rather than of client authentication.
        var (status, body) = await client.PostFormAsync(
            "/connect/token",
            TokenRequest(
                clientId,
                CreateAssertion(clientId, key, JwtConstants.HeaderType, subject: "someone-else")));

        Assert.NotEqual(HttpStatusCode.OK, status);
        Assert.Equal(Errors.InvalidClient, body.GetProperty("error").GetString());
    }

    [Theory]
    // Wrong recipient and a not-before a long way ahead are both failures of
    // client authentication, and RFC 6749 5.2 names that invalid_client;
    // OpenIddict reports them as invalid_grant (conformance:
    // fapi2-...-par-test-par-endpoint-url-as-audience-fails and the nbf module).
    [InlineData("https://another.example/", 0)]
    [InlineData("https://sts.tests.local/", 600)]
    public async Task An_assertion_for_another_server_or_for_later_is_invalid_client(
        string audience,
        int notBeforeOffsetSeconds)
    {
        var (factory, client, clientId, key) = await CreateClientAsync();
        using var _ = factory;

        var (status, body) = await client.PostFormAsync(
            "/connect/token",
            TokenRequest(
                clientId,
                CreateAssertion(
                    clientId,
                    key,
                    JwtConstants.HeaderType,
                    clientId,
                    audience,
                    notBeforeOffsetSeconds)));

        Assert.NotEqual(HttpStatusCode.OK, status);
        Assert.Equal(Errors.InvalidClient, body.GetProperty("error").GetString());
    }

    private static Dictionary<string, string> TokenRequest(
        string clientId,
        string assertion) => new()
        {
            ["grant_type"] = "client_credentials",
            ["client_id"] = clientId,
            ["client_assertion_type"] = ClientAssertionTypes.JwtBearer,
            ["client_assertion"] = assertion,
            ["scope"] = TestDataSeeder.ScopeName,
        };

    private static async Task<(ManagementTestFactory Factory, HttpClient Client, string ClientId, ECDsaSecurityKey Key)>
        CreateClientAsync()
    {
        var algorithm = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var signingKey = new ECDsaSecurityKey(algorithm)
        {
            KeyId = Guid.NewGuid().ToString("N"),
        };
        var publicJwk = JsonWebKeyConverter.ConvertFromECDsaSecurityKey(signingKey);
        publicJwk.D = null;
        publicJwk.Use = JsonWebKeyUseNames.Sig;
        publicJwk.Alg = SecurityAlgorithms.EcdsaSha256;

        var factory = new ManagementTestFactory();
        await ((IAsyncLifetime)factory).InitializeAsync();
        var client = factory.CreateClient();
        var clientId = $"standard-assertion-{Guid.NewGuid():N}";
        using var created = await client.PostAsJsonAsync("/api/clients",
            new CreateClientRequest
            {
                ClientId = clientId,
                JwksJson = JsonSerializer.Serialize(new
                {
                    keys = new[]
                    {
                        new
                        {
                            publicJwk.Kty,
                            publicJwk.Kid,
                            publicJwk.Use,
                            publicJwk.Alg,
                            publicJwk.Crv,
                            publicJwk.X,
                            publicJwk.Y,
                        },
                    },
                }, new JsonSerializerOptions(JsonSerializerDefaults.Web)),
                GrantTypes = [Permissions.GrantTypes.ClientCredentials],
                Scopes = [TestDataSeeder.ScopeName],
            });
        Assert.Equal(HttpStatusCode.Created, created.StatusCode);

        return (factory, client, clientId, signingKey);
    }

    private static string CreateAssertion(
        string clientId,
        ECDsaSecurityKey key,
        string tokenType,
        string subject,
        string audience = "https://sts.tests.local/",
        int notBeforeOffsetSeconds = 0)
    {
        var now = DateTime.UtcNow;
        return new JsonWebTokenHandler().CreateToken(new SecurityTokenDescriptor
        {
            Issuer = clientId,
            Audience = audience,
            Subject = new ClaimsIdentity([
                new Claim(Claims.Subject, subject),
                new Claim(Claims.JwtId, Guid.NewGuid().ToString("N")),
            ]),
            IssuedAt = now,
            NotBefore = now.AddSeconds(notBeforeOffsetSeconds),
            Expires = now.AddSeconds(notBeforeOffsetSeconds).AddMinutes(2),
            TokenType = tokenType,
            SigningCredentials = new SigningCredentials(
                key,
                SecurityAlgorithms.EcdsaSha256),
        });
    }
}
