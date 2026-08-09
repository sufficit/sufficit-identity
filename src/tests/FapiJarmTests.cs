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

public sealed class FapiJarmTests
{
    [Fact]
    public async Task Jarm_response_signature_issuer_audience_and_lifetime_validate()
    {
        using var key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var securityKey = new ECDsaSecurityKey(key);
        var generator = new JarmResponseGenerator(
            new SigningCredentials(securityKey, SecurityAlgorithms.EcdsaSha256),
            "https://sts.tests.local",
            TimeSpan.FromMinutes(2));
        var encoded = generator.Generate(new OpenIddictResponse
        {
            Code = "authorization-code",
            State = "state-123",
        }, "client-123");

        var validation = await new JsonWebTokenHandler().ValidateTokenAsync(
            encoded,
            new TokenValidationParameters
            {
                ValidIssuer = "https://sts.tests.local/",
                ValidAudience = "client-123",
                IssuerSigningKey = securityKey,
                ValidateIssuer = true,
                ValidateAudience = true,
                ValidateIssuerSigningKey = true,
                ValidateLifetime = true,
            });

        Assert.True(validation.IsValid, validation.Exception?.Message);
        var jwt = new JsonWebTokenHandler().ReadJsonWebToken(encoded);
        Assert.Equal("authorization-code", jwt.GetClaim("code").Value);
        Assert.Equal("state-123", jwt.GetClaim("state").Value);
    }

    [Fact]
    public async Task Jarm_signed_then_encrypted_response_produces_a_five_part_JWE()
    {
        // Signed JARM = 3 compact-serialization parts; signed+encrypted = 5.
        using var signingKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var signingCredentials = new SigningCredentials(
            new ECDsaSecurityKey(signingKey), SecurityAlgorithms.EcdsaSha256);

        // RSA key for JWE encryption (FAPI 2.0 Advancing Profile shape).
        using var rsa = RSA.Create(2048);
        var encryptionRsaKey = new RsaSecurityKey(rsa);
        var encryptionCredentials = new EncryptingCredentials(
            encryptionRsaKey, SecurityAlgorithms.RsaOAEP, SecurityAlgorithms.Aes256CbcHmacSha512);

        var generator = new JarmResponseGenerator(
            signingCredentials,
            "https://sts.tests.local",
            TimeSpan.FromMinutes(2),
            encryptionCredentials);

        var encoded = generator.Generate(new OpenIddictResponse
        {
            Code = "enc-auth-code",
        }, "client-jwe");

        // A JWE has 5 dot-separated parts; a JWS has 3.
        Assert.Equal(5, encoded.Split('.').Length);

        // Decrypt + validate the inner signed JWT.
        var handler = new JsonWebTokenHandler();
        var decryption = await handler.ValidateTokenAsync(encoded,
            new TokenValidationParameters
            {
                ValidIssuer = "https://sts.tests.local/",
                ValidAudience = "client-jwe",
                IssuerSigningKey = new ECDsaSecurityKey(signingKey),
                TokenDecryptionKey = encryptionRsaKey,
                ValidateIssuer = true,
                ValidateAudience = true,
                ValidateIssuerSigningKey = true,
                ValidateLifetime = true,
            });
        Assert.True(decryption.IsValid, decryption.Exception?.Message);
    }

    [Fact]
    public async Task Jarm_encryption_resolves_the_recipient_public_key_per_client()
    {
        using var factory = SufficitIdentityTestFactory.CreateIsolated(
            new Dictionary<string, string?>
            {
                ["Sufficit:Identity:Jarm:Enabled"] = "true",
                ["Sufficit:Identity:Jarm:Encryption:Enabled"] = "true",
            });
        await ((IAsyncLifetime)factory).InitializeAsync();
        using var rsa = RSA.Create(2048);
        var publicJwk = JsonWebKeyConverter.ConvertFromRSASecurityKey(
            new RsaSecurityKey(rsa) { KeyId = "client-encryption-key" });
        publicJwk.D = null;
        publicJwk.DP = null;
        publicJwk.DQ = null;
        publicJwk.P = null;
        publicJwk.Q = null;
        publicJwk.QI = null;
        publicJwk.Use = "enc";
        var keySet = new JsonWebKeySet();
        keySet.Keys.Add(publicJwk);
        await using var scope = factory.Services.CreateAsyncScope();
        var applications = scope.ServiceProvider
            .GetRequiredService<IOpenIddictApplicationManager>();
        await applications.CreateAsync(new OpenIddictApplicationDescriptor
        {
            ClientId = "jarm-encryption-client",
            ClientType = OpenIddictConstants.ClientTypes.Public,
            ConsentType = OpenIddictConstants.ConsentTypes.Explicit,
            JsonWebKeySet = keySet,
        });
        var resolver = scope.ServiceProvider.GetRequiredService<
            IJarmClientEncryptionCredentialsResolver>();

        var credentials = await resolver.ResolveAsync(
            "jarm-encryption-client");
        var missing = await resolver.ResolveAsync("missing-client");

        Assert.NotNull(credentials);
        Assert.Equal("client-encryption-key", credentials.Key.KeyId);
        Assert.Null(missing);
    }

    [Fact]
    public async Task Jarm_encryption_resolves_ec_recipient_with_ecdh_key_management()
    {
        using var factory = SufficitIdentityTestFactory.CreateIsolated(
            new Dictionary<string, string?>
            {
                ["Sufficit:Identity:Jarm:Enabled"] = "true",
                ["Sufficit:Identity:Jarm:Encryption:Enabled"] = "true",
            });
        await ((IAsyncLifetime)factory).InitializeAsync();

        using var ec = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var publicJwk = JsonWebKeyConverter.ConvertFromECDsaSecurityKey(
            new ECDsaSecurityKey(ec) { KeyId = "client-ec-encryption-key" });
        publicJwk.Use = "enc";
        publicJwk.D = null;

        var keySet = new JsonWebKeySet();
        keySet.Keys.Add(publicJwk);
        await using var scope = factory.Services.CreateAsyncScope();
        var applications = scope.ServiceProvider
            .GetRequiredService<IOpenIddictApplicationManager>();
        await applications.CreateAsync(new OpenIddictApplicationDescriptor
        {
            ClientId = "jarm-ec-encryption-client",
            ClientType = OpenIddictConstants.ClientTypes.Public,
            ConsentType = OpenIddictConstants.ConsentTypes.Explicit,
            JsonWebKeySet = keySet,
        });

        var resolver = scope.ServiceProvider.GetRequiredService<
            IJarmClientEncryptionCredentialsResolver>();
        var credentials = await resolver.ResolveAsync("jarm-ec-encryption-client");

        Assert.NotNull(credentials);
        Assert.Equal("client-ec-encryption-key", credentials.Key.KeyId);
        Assert.Equal("ECDH-ES+A256KW", credentials.Alg);
    }

    [Fact]
    public async Task Jarm_query_mode_returns_one_signed_response_parameter()
    {
        using var factory = SufficitIdentityTestFactory.CreateIsolated(
            new Dictionary<string, string?>
            {
                ["Sufficit:Identity:Jarm:Enabled"] = "true",
            });
        await ((IAsyncLifetime)factory).InitializeAsync();

        var client = factory.CreateClient(new WebApplicationFactoryClientOptions
        {
            AllowAutoRedirect = false,
        });
        await TestOnlyEndpoints.SignInAsync(client, TestDataSeeder.DefaultUsername);

        var verifier = WebEncoders.Base64UrlEncode(RandomNumberGenerator.GetBytes(48));
        var challenge = WebEncoders.Base64UrlEncode(
            SHA256.HashData(Encoding.ASCII.GetBytes(verifier)));
        const string state = "jarm-state";
        var uri = QueryHelpers.AddQueryString("/connect/authorize",
            new Dictionary<string, string?>
            {
                ["response_type"] = "code",
                ["response_mode"] = "query.jwt",
                ["client_id"] = TestDataSeeder.AuthorizationCodeClientId,
                ["redirect_uri"] = TestDataSeeder.AuthorizationCodeRedirectUri,
                ["scope"] = "openid " + TestDataSeeder.ScopeName,
                ["state"] = state,
                ["code_challenge"] = challenge,
                ["code_challenge_method"] = "S256",
            });

        using var response = await client.GetAsync(uri);
        Assert.Equal(HttpStatusCode.Redirect, response.StatusCode);
        var query = QueryHelpers.ParseQuery(response.Headers.Location!.Query);
        Assert.Single(query);
        var encoded = query["response"].ToString();
        Assert.False(string.IsNullOrWhiteSpace(encoded));

        var jwt = new JsonWebTokenHandler().ReadJsonWebToken(encoded);
        Assert.Equal("oauth-authz-resp+jwt", jwt.Typ);
        Assert.Equal("https://sts.tests.local/", jwt.Issuer);
        Assert.Equal(TestDataSeeder.AuthorizationCodeClientId, jwt.Audiences.Single());
        Assert.Equal(state, jwt.GetClaim("state").Value);
        Assert.False(string.IsNullOrWhiteSpace(jwt.GetClaim("code").Value));
        Assert.True(jwt.ValidTo > DateTime.UtcNow);

        var jwksJson = await client.GetStringAsync(
            "/.well-known/openid-configuration/jwks");
        var jwks = new JsonWebKeySet(jwksJson);
        Assert.Contains(jwks.Keys, key => key.Kid == jwt.Kid);
        var validation = await new JsonWebTokenHandler().ValidateTokenAsync(
            encoded,
            new TokenValidationParameters
            {
                ValidIssuer = "https://sts.tests.local/",
                ValidAudience = TestDataSeeder.AuthorizationCodeClientId,
                IssuerSigningKeys = jwks.Keys,
                ValidateIssuer = true,
                ValidateAudience = true,
                ValidateIssuerSigningKey = true,
                ValidateLifetime = true,
            });
        Assert.True(validation.IsValid, validation.Exception?.Message);
    }

    [Fact]
    public async Task Jarm_signs_authorization_error_responses_too()
    {
        using var factory = SufficitIdentityTestFactory.CreateIsolated(
            new Dictionary<string, string?>
            {
                ["Sufficit:Identity:Jarm:Enabled"] = "true",
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
                ["response_mode"] = "query.jwt",
                ["client_id"] = TestDataSeeder.AuthorizationCodeClientId,
                ["redirect_uri"] = TestDataSeeder.AuthorizationCodeRedirectUri,
                ["scope"] = "openid",
                ["state"] = "error-state",
                ["prompt"] = "none",
                ["code_challenge"] = challenge,
                ["code_challenge_method"] = "S256",
            });

        using var response = await client.GetAsync(uri);
        Assert.Equal(HttpStatusCode.Redirect, response.StatusCode);
        var parameters = QueryHelpers.ParseQuery(response.Headers.Location!.Query);
        Assert.Single(parameters);
        var jwt = new JsonWebTokenHandler().ReadJsonWebToken(
            parameters["response"].ToString());
        Assert.Equal("login_required", jwt.GetClaim("error").Value);
        Assert.Equal("error-state", jwt.GetClaim("state").Value);
        Assert.False(jwt.TryGetPayloadValue("code", out string _));
    }

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
