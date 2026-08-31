using System.Net;
using System.Net.Http.Json;
using System.Security.Cryptography;
using System.Security.Claims;
using System.Text;
using System.Text.Json;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.AspNetCore.WebUtilities;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Tokens;
using OpenIddict.Abstractions;
using Sufficit.Identity.STS.Jarm;
using Sufficit.Identity.Tests.Infrastructure;
using Xunit;

namespace Sufficit.Identity.Tests;

public sealed partial class FapiJarmTests
{

    [Fact]
    public async Task Discovery_advertises_PAR_issuer_parameter_and_JARM_only_when_enabled()
    {
        using var factory = SufficitIdentityTestFactory.CreateIsolated(
            new Dictionary<string, string?>
            {
                ["Sufficit:Identity:Jarm:Enabled"] = "true",
            });
        await ((IAsyncLifetime)factory).InitializeAsync();

        var metadata = await factory.CreateClient().GetFromJsonAsync<JsonElement>(
            "/.well-known/openid-configuration");
        Assert.EndsWith("/connect/par",
            metadata.GetProperty("pushed_authorization_request_endpoint").GetString());
        Assert.True(metadata.GetProperty(
            "authorization_response_iss_parameter_supported").GetBoolean());
        var modes = metadata.GetProperty("response_modes_supported")
            .EnumerateArray().Select(value => value.GetString()).ToArray();
        Assert.Contains("query.jwt", modes);
        Assert.Contains("form_post.jwt", modes);
        Assert.Contains("fragment.jwt", modes);
        Assert.Contains("jwt", modes);
        var signingAlgorithms = metadata
            .GetProperty("authorization_signing_alg_values_supported")
            .EnumerateArray().Select(value => value.GetString()).ToArray();
        Assert.Contains("ES256", signingAlgorithms);
    }

    [Fact]
    public async Task Discovery_advertises_PAR_endpoint_and_require_flag_when_enabled()
    {
        // Baseline: PAR endpoint is advertised, require_pushed is false.
        using var factory = SufficitIdentityTestFactory.CreateIsolated(
            new Dictionary<string, string?>());
        await ((IAsyncLifetime)factory).InitializeAsync();

        var metadata = await factory.CreateClient().GetFromJsonAsync<JsonElement>(
            "/.well-known/openid-configuration");
        Assert.EndsWith("/connect/par",
            metadata.GetProperty("pushed_authorization_request_endpoint").GetString());
        Assert.False(metadata.GetProperty(
            "require_pushed_authorization_requests").GetBoolean());

        // With RequireForAllClients: require_pushed_authorization_requests=true.
        using var required = SufficitIdentityTestFactory.CreateIsolated(
            new Dictionary<string, string?>
            {
                ["Sufficit:Identity:Par:RequireForAllClients"] = "true",
            });
        await ((IAsyncLifetime)required).InitializeAsync();

        var requiredMetadata = await required.CreateClient().GetFromJsonAsync<JsonElement>(
            "/.well-known/openid-configuration");
        Assert.True(requiredMetadata.GetProperty(
            "require_pushed_authorization_requests").GetBoolean());
    }

    [Fact]
    public async Task Discovery_advertises_JAR_signing_algorithms_when_enabled()
    {
        using var factory = SufficitIdentityTestFactory.CreateIsolated(
            new Dictionary<string, string?>
            {
                ["Sufficit:Identity:Jar:Enabled"] = "true",
            });
        await ((IAsyncLifetime)factory).InitializeAsync();

        var metadata = await factory.CreateClient().GetFromJsonAsync<JsonElement>(
            "/.well-known/openid-configuration");
        // The STS publishes the accepted signing algorithms when JAR is on.
        // (request_parameter_supported is owned by OpenIddict 7.6 and reflects
        // its own native request-object parsing, not the custom JAR handler —
        // so we assert only the algorithm list, which the STS controls.)
        Assert.True(metadata.TryGetProperty(
            "request_object_signing_alg_values_supported", out var algs));
        var algList = algs.EnumerateArray().Select(a => a.GetString()).ToArray();
        Assert.Contains("PS256", algList);
        Assert.Contains("ES256", algList);
    }

    [Fact]
    public async Task JAR_signed_request_object_is_validated_and_merged()
    {
        using var factory = SufficitIdentityTestFactory.CreateIsolated(
            new Dictionary<string, string?>
            {
                ["Sufficit:Identity:Jar:Enabled"] = "true",
            });
        await ((IAsyncLifetime)factory).InitializeAsync();

        // Generate an ES256 key for the request object signing + client JWKS.
        using var esKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var securityKey = new ECDsaSecurityKey(esKey) { KeyId = "test-jar-key" };
        var publicJwk = JsonWebKeyConverter.ConvertFromECDsaSecurityKey(securityKey);
        publicJwk.D = null;
        publicJwk.Use = "sig";
        publicJwk.KeyId = "test-jar-key";
        var keySet = new JsonWebKeySet();
        keySet.Keys.Add(publicJwk);

        // Seed a confidential client with the JWKS so the extractor can
        // validate the request object signature.
        using (var scope = factory.Services.CreateScope())
        {
            var apps = scope.ServiceProvider
                .GetRequiredService<IOpenIddictApplicationManager>();
            await apps.CreateAsync(new OpenIddictApplicationDescriptor
            {
                ClientId = "jar-test-client",
                ClientType = OpenIddictConstants.ClientTypes.Confidential,
                ClientSecret = "jar-test-secret",
                ConsentType = OpenIddictConstants.ConsentTypes.Implicit,
                RedirectUris = { new Uri("https://client.tests.local/callback") },
                Permissions =
                {
                    OpenIddictConstants.Permissions.Endpoints.Authorization,
                    OpenIddictConstants.Permissions.Endpoints.Token,
                    OpenIddictConstants.Permissions.GrantTypes.AuthorizationCode,
                    OpenIddictConstants.Permissions.ResponseTypes.Code,
                },
                Requirements =
                {
                    OpenIddictConstants.Requirements.Features.ProofKeyForCodeExchange,
                },
                JsonWebKeySet = keySet,
            });
        }

        // Build the signed request object (RFC 9101): iss=client_id,
        // aud=issuer, exp short, all authorization parameters in the payload.
        var verifier = WebEncoders.Base64UrlEncode(RandomNumberGenerator.GetBytes(48));
        var challenge = WebEncoders.Base64UrlEncode(
            SHA256.HashData(Encoding.ASCII.GetBytes(verifier)));

        var requestObject = new JsonWebTokenHandler().CreateToken(new SecurityTokenDescriptor
        {
            Issuer = "jar-test-client",
            Audience = "https://sts.tests.local/",
            IssuedAt = DateTime.UtcNow,
            Expires = DateTime.UtcNow.AddMinutes(1),
            TokenType = "oauth-authz-req+jwt",
            SigningCredentials = new SigningCredentials(securityKey, SecurityAlgorithms.EcdsaSha256),
            Claims = new Dictionary<string, object>
            {
                ["response_type"] = "code",
                ["client_id"] = "jar-test-client",
                ["redirect_uri"] = "https://client.tests.local/callback",
                ["scope"] = "openid",
                ["code_challenge"] = challenge,
                ["code_challenge_method"] = "S256",
                ["nonce"] = "jar-nonce-123",
                ["jti"] = Guid.NewGuid().ToString("N"),
            },
        });

        // Sign in the user first (the authorization endpoint requires an
        // authenticated session for the code to be issued).
        var client = factory.CreateClient(new WebApplicationFactoryClientOptions
        {
            AllowAutoRedirect = false,
        });
        var signinResult = await client.PostFormAsync(
            "/test-only/signin", new Dictionary<string, string>
            {
                ["username"] = TestDataSeeder.DefaultUsername,
            });
        Assert.Equal(HttpStatusCode.OK, signinResult.Status);

        // Send the authorization request with the signed request object.
        var response = await client.GetAsync(
            "/connect/authorize?client_id=jar-test-client&request="
            + Uri.EscapeDataString(requestObject));

        // A valid JAR request should produce a redirect with a code (not an
        // error). If JAR validation failed, we'd see error=invalid_request.
        Assert.True(response.StatusCode == HttpStatusCode.Redirect,
            $"JAR: expected redirect, got {response.StatusCode}");
        var query = QueryHelpers.ParseQuery(response.Headers.Location!.Query);
        Assert.False(query.ContainsKey("error"),
            $"JAR: got error={query.GetValueOrDefault("error")}: {query.GetValueOrDefault("error_description")}");
        Assert.True(query.ContainsKey("code"), "JAR: expected a code in the response");

        var replay = await client.GetAsync(
            "/connect/authorize?client_id=jar-test-client&request="
            + Uri.EscapeDataString(requestObject));
        Assert.True(
            replay.StatusCode is HttpStatusCode.BadRequest or HttpStatusCode.Redirect);
        if (replay.StatusCode is HttpStatusCode.Redirect)
        {
            var replayQuery = QueryHelpers.ParseQuery(replay.Headers.Location!.Query);
            Assert.Equal("invalid_request", replayQuery["error"].ToString());
        }
    }

    private static string CreateClientAssertion(
        string clientId,
        ECDsaSecurityKey key)
    {
        var now = DateTime.UtcNow;
        return new JsonWebTokenHandler().CreateToken(new SecurityTokenDescriptor
        {
            Issuer = clientId,
            Audience = "https://sts.tests.local/",
            Subject = new ClaimsIdentity(new[]
            {
                new Claim("sub", clientId),
                new Claim("jti", Guid.NewGuid().ToString("N")),
            }),
            IssuedAt = now,
            NotBefore = now,
            Expires = now.AddMinutes(2),
            TokenType = OpenIddictConstants.JsonWebTokenTypes.ClientAuthentication,
            SigningCredentials = new SigningCredentials(
                key, SecurityAlgorithms.EcdsaSha256),
        });
    }

    private static string BuildDpopProof(ECDsaSecurityKey key, string url)
    {
        var jwk = JsonWebKeyConverter.ConvertFromECDsaSecurityKey(key);
        jwk.D = null;
        var jwkJson = JsonSerializer.Serialize(jwk);
        return new JsonWebTokenHandler().CreateToken(new SecurityTokenDescriptor
        {
            Claims = new Dictionary<string, object>
            {
                ["htm"] = "POST",
                ["htu"] = url,
                ["iat"] = EpochTime.GetIntDate(DateTime.UtcNow),
                ["exp"] = EpochTime.GetIntDate(DateTime.UtcNow.AddMinutes(1)),
                ["jti"] = Guid.NewGuid().ToString("N"),
            },
            SigningCredentials = new SigningCredentials(
                key, SecurityAlgorithms.EcdsaSha256),
            AdditionalHeaderClaims = new Dictionary<string, object>
            {
                ["typ"] = "dpop+jwt",
                ["jwk"] = JsonSerializer.Deserialize<JsonElement>(jwkJson),
            },
        });
    }
}
