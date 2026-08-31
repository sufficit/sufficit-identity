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
    public async Task Invalid_par_request_returns_an_oauth_json_error()
    {
        using var factory = SufficitIdentityTestFactory.CreateIsolated(
            new Dictionary<string, string?>());
        await ((IAsyncLifetime)factory).InitializeAsync();
        using var client = factory.CreateClient(new WebApplicationFactoryClientOptions
        {
            AllowAutoRedirect = false,
        });
        using var content = new FormUrlEncodedContent(
            Array.Empty<KeyValuePair<string, string>>());

        using var response = await client.PostAsync("/connect/par", content);
        var payload = await response.Content.ReadFromJsonAsync<JsonElement>();

        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
        Assert.Equal("application/json", response.Content.Headers.ContentType?.MediaType);
        Assert.Equal("no-store", response.Headers.CacheControl?.ToString());
        Assert.True(payload.TryGetProperty("error", out var error));
        Assert.False(string.IsNullOrWhiteSpace(error.GetString()));
    }

    [Fact]
    public async Task Fapi_client_cannot_bypass_PAR_at_authorization_endpoint()
    {
        using var factory = SufficitIdentityTestFactory.CreateIsolated(
            new Dictionary<string, string?>
            {
                ["Sufficit:Identity:Dpop:Enabled"] = "true",
                ["Sufficit:Identity:Fapi2:Enabled"] = "true",
                ["Sufficit:Identity:Fapi2:ClientIds:0"] =
                    TestDataSeeder.AuthorizationCodeClientId,
            });
        await ((IAsyncLifetime)factory).InitializeAsync();

        var client = factory.CreateClient(new WebApplicationFactoryClientOptions
        {
            AllowAutoRedirect = false,
        });
        var verifier = WebEncoders.Base64UrlEncode(RandomNumberGenerator.GetBytes(48));
        var challenge = WebEncoders.Base64UrlEncode(
            SHA256.HashData(Encoding.ASCII.GetBytes(verifier)));
        var uri = QueryHelpers.AddQueryString("/connect/authorize",
            new Dictionary<string, string?>
            {
                ["response_type"] = "code",
                ["client_id"] = TestDataSeeder.AuthorizationCodeClientId,
                ["redirect_uri"] = TestDataSeeder.AuthorizationCodeRedirectUri,
                ["scope"] = "openid",
                ["code_challenge"] = challenge,
                ["code_challenge_method"] = "S256",
            });

        using var response = await client.GetAsync(uri);
        Assert.NotEqual(HttpStatusCode.OK, response.StatusCode);

        if (response.Headers.Location is { } location)
        {
            Assert.Equal("invalid_request",
                QueryHelpers.ParseQuery(location.Query)["error"].ToString());
        }
        else
        {
            // Depending on the status-code-pages integration point,
            // OpenIddict may serialize a non-redirectable protocol error as
            // JSON or as application/x-www-form-urlencoded text.
            Assert.Contains("invalid_request",
                await response.Content.ReadAsStringAsync(),
                StringComparison.Ordinal);
        }
    }

    [Fact]
    public async Task Fapi_PAR_accepts_private_key_jwt_PKCE_and_DPoP_code_binding()
    {
        const string clientId = "fapi-private-key-client";
        const string redirectUri = "https://fapi-client.tests.local/callback";
        using var clientKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var clientSecurityKey = new ECDsaSecurityKey(clientKey)
        {
            KeyId = Guid.NewGuid().ToString("N"),
        };
        var publicJwk = JsonWebKeyConverter.ConvertFromECDsaSecurityKey(
            clientSecurityKey);
        publicJwk.D = null;
        publicJwk.Use = "sig";
        var keySet = new JsonWebKeySet();
        keySet.Keys.Add(publicJwk);

        using var factory = SufficitIdentityTestFactory.CreateIsolated(
            new Dictionary<string, string?>
            {
                ["Sufficit:Identity:Dpop:Enabled"] = "true",
                ["Sufficit:Identity:Fapi2:Enabled"] = "true",
                ["Sufficit:Identity:Fapi2:ClientIds:0"] = clientId,
            });
        await ((IAsyncLifetime)factory).InitializeAsync();
        using (var scope = factory.Services.CreateScope())
        {
            var applications = scope.ServiceProvider
                .GetRequiredService<IOpenIddictApplicationManager>();
            await applications.CreateAsync(new OpenIddictApplicationDescriptor
            {
                ClientId = clientId,
                ClientType = OpenIddictConstants.ClientTypes.Confidential,
                ConsentType = OpenIddictConstants.ConsentTypes.Implicit,
                JsonWebKeySet = keySet,
                RedirectUris = { new Uri(redirectUri) },
                Permissions =
                {
                    OpenIddictConstants.Permissions.Endpoints.Authorization,
                    OpenIddictConstants.Permissions.Endpoints.PushedAuthorization,
                    OpenIddictConstants.Permissions.Endpoints.Token,
                    OpenIddictConstants.Permissions.GrantTypes.AuthorizationCode,
                    OpenIddictConstants.Permissions.ResponseTypes.Code,
                    OpenIddictConstants.Permissions.Prefixes.Scope +
                        OpenIddictConstants.Scopes.OpenId,
                },
                Requirements =
                {
                    OpenIddictConstants.Requirements.Features.ProofKeyForCodeExchange,
                    OpenIddictConstants.Requirements.Features.PushedAuthorizationRequests,
                },
            });
        }

        var assertion = CreateClientAssertion(clientId, clientSecurityKey);
        var verifier = WebEncoders.Base64UrlEncode(RandomNumberGenerator.GetBytes(48));
        var challenge = WebEncoders.Base64UrlEncode(
            SHA256.HashData(Encoding.ASCII.GetBytes(verifier)));
        using var dpopAlgorithm = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var dpopKey = new ECDsaSecurityKey(dpopAlgorithm);
        var dpopPublicJwk = JsonWebKeyConverter.ConvertFromECDsaSecurityKey(dpopKey);
        dpopPublicJwk.D = null;
        var dpopJkt = Base64UrlEncoder.Encode(dpopPublicJwk.ComputeJwkThumbprint());
        var client = factory.CreateClient(new WebApplicationFactoryClientOptions
        {
            AllowAutoRedirect = false,
        });

        var (status, body) = await client.PostFormAsync("/connect/par",
            new Dictionary<string, string>
            {
                ["client_id"] = clientId,
                ["client_assertion_type"] =
                    OpenIddictConstants.ClientAssertionTypes.JwtBearer,
                ["client_assertion"] = assertion,
                ["response_type"] = "code",
                ["redirect_uri"] = redirectUri,
                ["scope"] = "openid",
                ["code_challenge"] = challenge,
                ["code_challenge_method"] = "S256",
                ["dpop_jkt"] = dpopJkt,
            });

        Assert.True(status == HttpStatusCode.Created,
            $"FAPI PAR failed with {(int)status}: {body}");
        Assert.StartsWith("urn:ietf:params:oauth:request_uri:",
            body.GetProperty("request_uri").GetString());
        Assert.InRange(body.GetProperty("expires_in").GetInt32(), 1, 599);

        await TestOnlyEndpoints.SignInAsync(client, TestDataSeeder.DefaultUsername);
        using var authorization = await client.GetAsync(QueryHelpers.AddQueryString(
            "/connect/authorize",
            new Dictionary<string, string?>
            {
                ["client_id"] = clientId,
                ["request_uri"] = body.GetProperty("request_uri").GetString(),
            }));
        Assert.Equal(HttpStatusCode.Redirect, authorization.StatusCode);
        var authorizationResponse = QueryHelpers.ParseQuery(
            authorization.Headers.Location!.Query);
        var code = authorizationResponse["code"].ToString();
        Assert.False(string.IsNullOrWhiteSpace(code));

        var tokenUrl = new Uri(client.BaseAddress!, "connect/token").AbsoluteUri;
        client.DefaultRequestHeaders.Add("DPoP", BuildDpopProof(dpopKey, tokenUrl));
        var (tokenStatus, tokenBody) = await client.PostFormAsync("/connect/token",
            new Dictionary<string, string>
            {
                ["grant_type"] = "authorization_code",
                ["client_id"] = clientId,
                ["client_assertion_type"] =
                    OpenIddictConstants.ClientAssertionTypes.JwtBearer,
                ["client_assertion"] =
                    CreateClientAssertion(clientId, clientSecurityKey),
                ["code"] = code,
                ["redirect_uri"] = redirectUri,
                ["code_verifier"] = verifier,
            });
        Assert.True(tokenStatus == HttpStatusCode.OK,
            $"FAPI token exchange failed with {(int)tokenStatus}: {tokenBody}");
        Assert.Equal("DPoP", tokenBody.GetProperty("token_type").GetString());
    }

    [Fact]
    public async Task PAR_issues_a_request_uri_and_required_client_can_authorize_with_it()
    {
        using var factory = SufficitIdentityTestFactory.CreateIsolated(
            new Dictionary<string, string?>
            {
                ["Sufficit:Identity:Dpop:Enabled"] = "true",
                ["Sufficit:Identity:Fapi2:Enabled"] = "true",
                ["Sufficit:Identity:Fapi2:ClientIds:0"] = "future-fapi-client",
            });
        await ((IAsyncLifetime)factory).InitializeAsync();

        const string clientId = "par-integration-client";
        const string clientSecret = "par-integration-secret";
        const string redirectUri = "https://par-client.tests.local/callback";
        using (var scope = factory.Services.CreateScope())
        {
            var applications = scope.ServiceProvider
                .GetRequiredService<IOpenIddictApplicationManager>();
            var descriptor = new OpenIddictApplicationDescriptor
            {
                ClientId = clientId,
                ClientSecret = clientSecret,
                ClientType = OpenIddictConstants.ClientTypes.Confidential,
                ConsentType = OpenIddictConstants.ConsentTypes.Implicit,
                RedirectUris = { new Uri(redirectUri) },
                Permissions =
                {
                    OpenIddictConstants.Permissions.Endpoints.Authorization,
                    OpenIddictConstants.Permissions.Endpoints.PushedAuthorization,
                    OpenIddictConstants.Permissions.Endpoints.Token,
                    OpenIddictConstants.Permissions.GrantTypes.AuthorizationCode,
                    OpenIddictConstants.Permissions.ResponseTypes.Code,
                    OpenIddictConstants.Permissions.Prefixes.Scope +
                        OpenIddictConstants.Scopes.OpenId,
                },
                Requirements =
                {
                    OpenIddictConstants.Requirements.Features.ProofKeyForCodeExchange,
                    OpenIddictConstants.Requirements.Features.PushedAuthorizationRequests,
                },
            };
            await applications.CreateAsync(descriptor);
        }

        var client = factory.CreateClient(new WebApplicationFactoryClientOptions
        {
            AllowAutoRedirect = false,
        });
        await TestOnlyEndpoints.SignInAsync(client, TestDataSeeder.DefaultUsername);
        var verifier = WebEncoders.Base64UrlEncode(RandomNumberGenerator.GetBytes(48));
        var challenge = WebEncoders.Base64UrlEncode(
            SHA256.HashData(Encoding.ASCII.GetBytes(verifier)));

        var (parStatus, parBody) = await client.PostFormAsync("/connect/par",
            new Dictionary<string, string>
            {
                ["client_id"] = clientId,
                ["client_secret"] = clientSecret,
                ["response_type"] = "code",
                ["redirect_uri"] = redirectUri,
                ["scope"] = "openid",
                ["state"] = "par-state",
                ["code_challenge"] = challenge,
                ["code_challenge_method"] = "S256",
            });
        Assert.True(parStatus == HttpStatusCode.Created,
            $"PAR failed with {(int)parStatus}: {parBody}");
        var requestUri = parBody.GetProperty("request_uri").GetString();
        Assert.StartsWith("urn:ietf:params:oauth:request_uri:", requestUri);
        Assert.InRange(parBody.GetProperty("expires_in").GetInt32(), 1, 599);

        using var authorization = await client.GetAsync(QueryHelpers.AddQueryString(
            "/connect/authorize",
            new Dictionary<string, string?>
            {
                ["client_id"] = clientId,
                ["request_uri"] = requestUri,
            }));
        Assert.Equal(HttpStatusCode.Redirect, authorization.StatusCode);
        var result = QueryHelpers.ParseQuery(authorization.Headers.Location!.Query);
        Assert.False(result.ContainsKey("error"));
        Assert.False(string.IsNullOrWhiteSpace(result["code"].ToString()));
        Assert.Equal("https://sts.tests.local/", result["iss"].ToString());
    }

    [Fact]
    public async Task PAR_required_for_all_clients_rejects_authorize_without_request_uri()
    {
        using var factory = SufficitIdentityTestFactory.CreateIsolated(
            new Dictionary<string, string?>
            {
                ["Sufficit:Identity:Par:RequireForAllClients"] = "true",
            });
        await ((IAsyncLifetime)factory).InitializeAsync();

        var client = factory.CreateClient(new WebApplicationFactoryClientOptions
        {
            AllowAutoRedirect = false,
        });

        // A direct authorize request (no request_uri) must be rejected. With
        // RequirePushedAuthorizationRequests, OpenIddict returns the error as
        // either a redirect with error=invalid_request or a 400 response.
        var response = await client.GetAsync(
            "/connect/authorize" +
            "?response_type=code" +
            "&client_id=" + TestDataSeeder.AuthorizationCodeClientId +
            "&redirect_uri=https://client.tests.local/callback" +
            "&code_challenge=" + WebEncoders.Base64UrlEncode(RandomNumberGenerator.GetBytes(32)) +
            "&code_challenge_method=S256&scope=openid");

        // The error is surfaced — either via a redirect carrying the error, or
        // as a direct 400. Both are acceptable rejection shapes.
        var isError = response.StatusCode == HttpStatusCode.BadRequest
            || (response.Headers.Location is { } location
                && QueryHelpers.ParseQuery(location.Query).ContainsKey("error"));
        Assert.True(isError,
            $"expected PAR-required rejection without request_uri, got {response.StatusCode}");
    }
}
