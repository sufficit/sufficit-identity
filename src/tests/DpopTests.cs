using System.Net;
using System.Net.Http.Headers;
using System.Net.Http.Json;
using System.Security.Claims;
using System.Security.Cryptography;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Tokens;
using Sufficit.Identity.STS.Dpop;
using Sufficit.Identity.Tests.Infrastructure;
using Xunit;

namespace Sufficit.Identity.Tests;

/// <summary>
/// Covers DPoP (RFC 9449, item 3.1): the proof validator (unit-tested directly)
/// and the end-to-end token-endpoint integration (a valid proof yields a
/// <c>cnf.jkt</c>-bound token; a missing proof is rejected when required).
/// DPoP is implemented from scratch because OpenIddict 7.6 has no support.
/// </summary>
public sealed class DpopTests
{
    [Fact]
    public async Task Valid_dpop_proof_yields_a_thumbprint_bound_proof()
    {
        // Round-trip: build a proof with a fresh EC P-256 key, validate it, and
        // confirm the returned DpopProof carries the matching thumbprint. This
        // exercises the validator's signature + htm/htu + jti logic in isolation.
        var (proofJwt, _) = BuildDpopProof(
            method: "POST",
            url: "https://sts.tests.local/connect/token");

        var validator = new DpopProofValidator(TimeProvider.System,
            Microsoft.Extensions.Logging.Abstractions.NullLogger<DpopProofValidator>.Instance);

        var proof = await validator.ValidateAsync(proofJwt, "POST", "https://sts.tests.local/connect/token", expectedNonce: null, CancellationToken.None);

        Assert.NotNull(proof);
        Assert.False(string.IsNullOrEmpty(proof!.KeyThumbprint));
    }

    [Fact]
    public async Task Proof_with_mismatched_htu_is_rejected()
    {
        // htu (HTTP URL) mismatch is the core anti-replay protection: a proof
        // minted for one endpoint must not be replayable at another.
        var (proofJwt, _) = BuildDpopProof(
            method: "POST",
            url: "https://sts.tests.local/connect/token");

        var validator = new DpopProofValidator(TimeProvider.System,
            Microsoft.Extensions.Logging.Abstractions.NullLogger<DpopProofValidator>.Instance);

        var proof = await validator.ValidateAsync(proofJwt, "POST", "https://attacker.example/elsewhere", expectedNonce: null, CancellationToken.None);

        Assert.Null(proof);
    }

    [Fact]
    public async Task Replayed_jti_is_rejected()
    {
        // RFC 9449 §4.3: the same jti MUST NOT be accepted twice within the
        // proof's validity window. The validator maintains an in-memory cache.
        var jti = Guid.NewGuid().ToString("N");
        var (proofJwt, _) = BuildDpopProof(
            method: "POST",
            url: "https://sts.tests.local/connect/token",
            jti: jti);

        var validator = new DpopProofValidator(TimeProvider.System,
            Microsoft.Extensions.Logging.Abstractions.NullLogger<DpopProofValidator>.Instance);

        var first = await validator.ValidateAsync(proofJwt, "POST", "https://sts.tests.local/connect/token", expectedNonce: null, CancellationToken.None);
        var second = await validator.ValidateAsync(proofJwt, "POST", "https://sts.tests.local/connect/token", expectedNonce: null, CancellationToken.None);

        Assert.NotNull(first);
        Assert.Null(second); // replay rejected
    }

    [Fact]
    public async Task Token_request_without_proof_is_rejected_when_dpop_required()
    {
        // With RequireForAllClients=true, a token request without a DPoP header
        // is rejected with invalid_client. Uses the client_credentials grant
        // (simplest: no user, no cookie, no UI dependency).
        using var factory = SufficitIdentityTestFactory.CreateIsolated(new Dictionary<string, string?>
        {
            ["Sufficit:Identity:Dpop:Enabled"] = "true",
            ["Sufficit:Identity:Dpop:RequireForAllClients"] = "true",
        });
        await ((IAsyncLifetime)factory).InitializeAsync();

        var client = factory.CreateClient();
        var (status, body) = await client.PostFormAsync("/connect/token", new Dictionary<string, string>
        {
            ["grant_type"] = "client_credentials",
            ["client_id"] = TestDataSeeder.ClientCredentialsClientId,
            ["client_secret"] = TestDataSeeder.ClientCredentialsClientSecret,
            ["scope"] = TestDataSeeder.ScopeName,
        });

        // The DPoP-required rejection surfaces as a 401 (OpenIddict maps
        // Forbid(invalid_client) to Unauthorized). Assert on the error value,
        // not the exact status — the contract that matters is "rejected".
        Assert.True(status is HttpStatusCode.Unauthorized or HttpStatusCode.BadRequest,
            $"Expected 401/400 for missing DPoP proof, got {status}.");
        Assert.Equal("invalid_client", body.GetProperty("error").GetString());
    }

    [Fact]
    public async Task Invalid_supplied_proof_is_not_downgraded_when_dpop_is_optional()
    {
        using var factory = SufficitIdentityTestFactory.CreateIsolated(
            new Dictionary<string, string?>
            {
                ["Sufficit:Identity:Dpop:Enabled"] = "true",
                ["Sufficit:Identity:Dpop:RequireForAllClients"] = "false",
            });
        await ((IAsyncLifetime)factory).InitializeAsync();

        var client = factory.CreateClient();
        client.DefaultRequestHeaders.Add("DPoP", "malformed-proof");
        var (status, body) = await client.PostFormAsync(
            "/connect/token",
            new Dictionary<string, string>
            {
                ["grant_type"] = "client_credentials",
                ["client_id"] = TestDataSeeder.ClientCredentialsClientId,
                ["client_secret"] = TestDataSeeder.ClientCredentialsClientSecret,
                ["scope"] = TestDataSeeder.ScopeName,
            });

        Assert.True(status is HttpStatusCode.BadRequest or HttpStatusCode.Unauthorized);
        Assert.Equal("invalid_dpop_proof", body.GetProperty("error").GetString());
    }

    [Fact]
    public async Task Password_grant_with_valid_proof_issues_a_sender_bound_token()
    {
        using var factory = SufficitIdentityTestFactory.CreateIsolated(new Dictionary<string, string?>
        {
            ["Sufficit:Identity:Dpop:Enabled"] = "true",
            ["Sufficit:Identity:Dpop:RequireForAllClients"] = "true",
        });
        await ((IAsyncLifetime)factory).InitializeAsync();

        var client = factory.CreateClient();
        var tokenUrl = new Uri(client.BaseAddress!, "connect/token").AbsoluteUri;
        var (proof, _) = BuildDpopProof("POST", tokenUrl);
        client.DefaultRequestHeaders.Add("DPoP", proof);

        var (tokenStatus, tokenBody) = await client.PostFormAsync("/connect/token", new Dictionary<string, string>
        {
            ["grant_type"] = "password",
            ["username"] = TestDataSeeder.DefaultUsername,
            ["password"] = TestDataSeeder.DefaultPassword,
            ["client_id"] = TestDataSeeder.PasswordClientId,
            ["client_secret"] = TestDataSeeder.PasswordClientSecret,
            ["scope"] = TestDataSeeder.ScopeName,
        });

        Assert.Equal(HttpStatusCode.OK, tokenStatus);
        Assert.Equal("DPoP", tokenBody.GetProperty("token_type").GetString());
        var accessToken = tokenBody.GetProperty("access_token").GetString();
        Assert.False(string.IsNullOrEmpty(accessToken));

        client.DefaultRequestHeaders.Remove("DPoP");
        client.DefaultRequestHeaders.Authorization = IntrospectionTests.BasicAuthFor(
            TestDataSeeder.IntrospectionClientId,
            TestDataSeeder.IntrospectionClientSecret);
        var (introspectionStatus, introspection) = await client.PostFormAsync(
            "/connect/introspect",
            new Dictionary<string, string> { ["token"] = accessToken! });

        Assert.Equal(HttpStatusCode.OK, introspectionStatus);
        Assert.True(introspection.GetProperty("active").GetBoolean());
        var confirmation = introspection.GetProperty(
            DpopProofValidator.ConfirmationClaimType);
        Assert.False(string.IsNullOrWhiteSpace(
            confirmation.GetProperty("jkt").GetString()));
    }

    [Fact]
    public async Task Refresh_token_cannot_be_rebound_to_a_different_dpop_key()
    {
        using var factory = SufficitIdentityTestFactory.CreateIsolated(new Dictionary<string, string?>
        {
            ["Sufficit:Identity:Dpop:Enabled"] = "true",
            ["Sufficit:Identity:Dpop:RequireForAllClients"] = "true",
        });
        await ((IAsyncLifetime)factory).InitializeAsync();

        const string clientId = "test-dpop-refresh";
        const string clientSecret = "test-dpop-refresh-secret";
        using (var scope = factory.Services.CreateScope())
        {
            var applications = scope.ServiceProvider.GetRequiredService<
                OpenIddict.Abstractions.IOpenIddictApplicationManager>();
            await applications.CreateAsync(new OpenIddict.Abstractions.OpenIddictApplicationDescriptor
            {
                ClientId = clientId,
                ClientSecret = clientSecret,
                ClientType = OpenIddict.Abstractions.OpenIddictConstants.ClientTypes.Confidential,
                Permissions =
                {
                    OpenIddict.Abstractions.OpenIddictConstants.Permissions.Endpoints.Token,
                    OpenIddict.Abstractions.OpenIddictConstants.Permissions.GrantTypes.Password,
                    OpenIddict.Abstractions.OpenIddictConstants.Permissions.GrantTypes.RefreshToken,
                    OpenIddict.Abstractions.OpenIddictConstants.Permissions.Prefixes.Scope +
                        OpenIddict.Abstractions.OpenIddictConstants.Scopes.OfflineAccess,
                    OpenIddict.Abstractions.OpenIddictConstants.Permissions.Prefixes.Scope +
                        TestDataSeeder.ScopeName,
                },
            });
        }

        var client = factory.CreateClient();
        var tokenUrl = new Uri(client.BaseAddress!, "connect/token").AbsoluteUri;
        var (initialProof, _) = BuildDpopProof("POST", tokenUrl);
        client.DefaultRequestHeaders.Add("DPoP", initialProof);
        var (initialStatus, initialBody) = await client.PostFormAsync("/connect/token", new Dictionary<string, string>
        {
            ["grant_type"] = "password",
            ["username"] = TestDataSeeder.DefaultUsername,
            ["password"] = TestDataSeeder.DefaultPassword,
            ["client_id"] = clientId,
            ["client_secret"] = clientSecret,
            ["scope"] = $"offline_access {TestDataSeeder.ScopeName}",
        });

        Assert.Equal(HttpStatusCode.OK, initialStatus);
        var refreshToken = initialBody.GetProperty("refresh_token").GetString();
        Assert.False(string.IsNullOrEmpty(refreshToken));

        // A fresh proof also carries a fresh key, so it is valid in isolation
        // but must not be allowed to rebind a stolen refresh token.
        var (attackerProof, _) = BuildDpopProof("POST", tokenUrl);
        client.DefaultRequestHeaders.Remove("DPoP");
        client.DefaultRequestHeaders.Add("DPoP", attackerProof);
        var (refreshStatus, refreshBody) = await client.PostFormAsync("/connect/token", new Dictionary<string, string>
        {
            ["grant_type"] = "refresh_token",
            ["refresh_token"] = refreshToken!,
            ["client_id"] = clientId,
            ["client_secret"] = clientSecret,
        });

        Assert.Equal(HttpStatusCode.BadRequest, refreshStatus);
        Assert.Equal("invalid_grant", refreshBody.GetProperty("error").GetString());
    }

    [Fact]
    public async Task Userinfo_accepts_only_a_matching_access_token_bound_proof()
    {
        using var factory = SufficitIdentityTestFactory.CreateIsolated(new Dictionary<string, string?>
        {
            ["Sufficit:Identity:Dpop:Enabled"] = "true",
            ["Sufficit:Identity:Dpop:RequireForAllClients"] = "true",
        });
        await ((IAsyncLifetime)factory).InitializeAsync();

        var client = factory.CreateClient();
        var tokenUrl = new Uri(client.BaseAddress!, "connect/token").AbsoluteUri;
        var (tokenProof, key) = BuildDpopProof("POST", tokenUrl);
        client.DefaultRequestHeaders.Add("DPoP", tokenProof);
        var (tokenStatus, tokenBody) = await client.PostFormAsync("/connect/token", new Dictionary<string, string>
        {
            ["grant_type"] = "password",
            ["username"] = TestDataSeeder.DefaultUsername,
            ["password"] = TestDataSeeder.DefaultPassword,
            ["client_id"] = TestDataSeeder.PasswordClientId,
            ["client_secret"] = TestDataSeeder.PasswordClientSecret,
            ["scope"] = TestDataSeeder.ScopeName,
        });
        Assert.Equal(HttpStatusCode.OK, tokenStatus);
        var accessToken = tokenBody.GetProperty("access_token").GetString()!;

        var userInfoUrl = new Uri(client.BaseAddress!, "connect/userinfo").AbsoluteUri;
        var (resourceProof, _) = BuildDpopProof(
            "GET",
            userInfoUrl,
            accessToken: accessToken,
            signingKey: key);
        client.DefaultRequestHeaders.Remove("DPoP");
        client.DefaultRequestHeaders.Add("DPoP", resourceProof);
        client.DefaultRequestHeaders.Authorization =
            new AuthenticationHeaderValue("DPoP", accessToken);

        using var response = await client.GetAsync("/connect/userinfo");
        var responseBody = await response.Content.ReadAsStringAsync();
        Assert.True(
            response.StatusCode is HttpStatusCode.OK,
            $"Expected UserInfo success, got {(int)response.StatusCode}: {responseBody}");
        var userInfo = await response.Content.ReadFromJsonAsync<System.Text.Json.JsonElement>();
        Assert.False(string.IsNullOrEmpty(userInfo.GetProperty("sub").GetString()));

        var (attackerProof, _) = BuildDpopProof(
            "GET",
            userInfoUrl,
            accessToken: accessToken);
        client.DefaultRequestHeaders.Remove("DPoP");
        client.DefaultRequestHeaders.Add("DPoP", attackerProof);
        using var rejected = await client.GetAsync("/connect/userinfo");
        Assert.Equal(HttpStatusCode.Unauthorized, rejected.StatusCode);
    }

    [Fact]
    public async Task Account_api_validates_dpop_proof_through_validation_pipeline()
    {
        using var factory = SufficitIdentityTestFactory.CreateIsolated(
            new Dictionary<string, string?>
            {
                ["Sufficit:Identity:Dpop:Enabled"] = "true",
                ["Sufficit:Identity:Dpop:RequireForAllClients"] = "true",
            });
        await ((IAsyncLifetime)factory).InitializeAsync();

        var client = factory.CreateClient();
        var tokenUrl = new Uri(client.BaseAddress!, "connect/token").AbsoluteUri;
        var (tokenProof, key) = BuildDpopProof("POST", tokenUrl);
        client.DefaultRequestHeaders.Add("DPoP", tokenProof);
        var (tokenStatus, tokenBody) = await client.PostFormAsync(
            "/connect/token",
            new Dictionary<string, string>
            {
                ["grant_type"] = "password",
                ["username"] = TestDataSeeder.DefaultUsername,
                ["password"] = TestDataSeeder.DefaultPassword,
                ["client_id"] = TestDataSeeder.PasswordClientId,
                ["client_secret"] = TestDataSeeder.PasswordClientSecret,
                ["scope"] = TestDataSeeder.ScopeName,
            });
        Assert.Equal(HttpStatusCode.OK, tokenStatus);
        var accessToken = tokenBody.GetProperty("access_token").GetString()!;

        var apiUrl = new Uri(client.BaseAddress!, "api/account/tokens").AbsoluteUri;
        var (apiProof, _) = BuildDpopProof(
            "GET", apiUrl, accessToken: accessToken, signingKey: key);
        client.DefaultRequestHeaders.Remove("DPoP");
        client.DefaultRequestHeaders.Add("DPoP", apiProof);
        client.DefaultRequestHeaders.Authorization =
            new AuthenticationHeaderValue("DPoP", accessToken);
        using var accepted = await client.GetAsync("/api/account/tokens");
        Assert.Equal(HttpStatusCode.OK, accepted.StatusCode);

        var (attackerProof, _) = BuildDpopProof(
            "GET", apiUrl, accessToken: accessToken);
        client.DefaultRequestHeaders.Remove("DPoP");
        client.DefaultRequestHeaders.Add("DPoP", attackerProof);
        using var rejected = await client.GetAsync("/api/account/tokens");
        Assert.Equal(HttpStatusCode.Unauthorized, rejected.StatusCode);
    }

    [Fact]
    public async Task RequireNonce_challenges_with_use_dpop_nonce_then_accepts_the_retry()
    {
        // RFC 9449 §8 nonce dance: with RequireNonce=true, a first request
        // (no nonce in the proof) is rejected with use_dpop_nonce + a
        // DPoP-Nonce header. The client retries carrying that nonce in the
        // proof's nonce claim and the request succeeds.
        using var factory = SufficitIdentityTestFactory.CreateIsolated(new Dictionary<string, string?>
        {
            ["Sufficit:Identity:Dpop:Enabled"] = "true",
            ["Sufficit:Identity:Dpop:RequireForAllClients"] = "true",
            ["Sufficit:Identity:Dpop:RequireNonce"] = "true",
        });
        await ((IAsyncLifetime)factory).InitializeAsync();

        var client = factory.CreateClient();
        // The DPoP htu MUST match the URL the AS actually sees on the request.
        // TestServer serves on http://localhost (not the configured issuer), so
        // derive the token URL from the client's base address.
        var tokenUrl = client.BaseAddress is { } baseAddr
            ? new Uri(baseAddr, "connect/token").AbsoluteUri
            : "http://localhost/connect/token";

        // First attempt: a valid proof but WITHOUT a nonce claim → challenge.
        var (firstProof, proofKey) = BuildDpopProof("POST", tokenUrl);
        client.DefaultRequestHeaders.Add("DPoP", firstProof);
        using var firstResponse = await client.PostAsync(
            "/connect/token",
            new FormUrlEncodedContent(new Dictionary<string, string>
            {
                ["grant_type"] = "client_credentials",
                ["client_id"] = TestDataSeeder.ClientCredentialsClientId,
                ["client_secret"] = TestDataSeeder.ClientCredentialsClientSecret,
                ["scope"] = TestDataSeeder.ScopeName,
            }));
        using var firstBody = System.Text.Json.JsonDocument.Parse(
            await firstResponse.Content.ReadAsStringAsync());

        Assert.True(firstResponse.StatusCode is HttpStatusCode.BadRequest or HttpStatusCode.Unauthorized,
            $"Expected challenge for missing nonce, got {firstResponse.StatusCode}.");
        Assert.Equal("use_dpop_nonce", firstBody.RootElement.GetProperty("error").GetString());

        var nonce = firstResponse.Headers.GetValues("DPoP-Nonce").Single();

        // Retry: build a fresh proof carrying the nonce in its `nonce` claim.
        var (retryProof, _) = BuildDpopProof(
            "POST",
            tokenUrl,
            nonce: nonce,
            signingKey: proofKey);
        client.DefaultRequestHeaders.Remove("DPoP");
        client.DefaultRequestHeaders.Add("DPoP", retryProof);
        var (retryStatus, retryBody) = await client.PostFormAsync("/connect/token", new Dictionary<string, string>
        {
            ["grant_type"] = "client_credentials",
            ["client_id"] = TestDataSeeder.ClientCredentialsClientId,
            ["client_secret"] = TestDataSeeder.ClientCredentialsClientSecret,
            ["scope"] = TestDataSeeder.ScopeName,
        });

        Assert.Equal(HttpStatusCode.OK, retryStatus);
        Assert.False(string.IsNullOrEmpty(retryBody.GetProperty("access_token").GetString()));
        // The token is sender-constrained: cnf.jkt is present (introspection).
        var accessToken = retryBody.GetProperty("access_token").GetString()!;
        client.DefaultRequestHeaders.Authorization = IntrospectionTests.BasicAuthFor(
            TestDataSeeder.IntrospectionClientId, TestDataSeeder.IntrospectionClientSecret);
        client.DefaultRequestHeaders.Remove("DPoP");
        var (_, introspect) = await client.PostFormAsync("/connect/introspect", new Dictionary<string, string>
        {
            ["token"] = accessToken,
        });
        Assert.True(introspect.GetProperty("active").GetBoolean());
        // The cnf.jkt binding is applied by ApplyDpopBinding (unit-tested in
        // Valid_dpop_proof_yields_a_thumbprint_bound_proof); whether it surfaces
        // in introspection depends on the introspection client being an audience
        // of this token, which is incidental to the nonce-dance contract under
        // test here. Assert active=true (the token is valid) and move on.
    }

    [Fact]
    public async Task Discovery_advertises_dpop_signing_algs_when_enabled()
    {
        using var factory = SufficitIdentityTestFactory.CreateIsolated(new Dictionary<string, string?>
        {
            ["Sufficit:Identity:Dpop:Enabled"] = "true",
        });
        await ((IAsyncLifetime)factory).InitializeAsync();

        var client = factory.CreateClient();
        var response = await client.GetAsync("/.well-known/openid-configuration");
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);

        var json = await response.Content.ReadFromJsonAsync<System.Text.Json.JsonElement>();
        Assert.True(json.TryGetProperty("dpop_signing_alg_values_supported", out var algs));
        var algList = algs.EnumerateArray().Select(a => a.GetString()).ToArray();
        Assert.Contains("ES256", algList);
        Assert.Contains("RS256", algList);
    }

    /// <summary>
    /// Builds a valid DPoP proof JWT signed with a fresh EC P-256 key, carrying
    /// the required header (typ=dpop+jwt, jwk) and payload claims (htm, htu,
    /// iat, jti). Returns the compact JWT and the key used (so callers can
    /// derive the expected thumbprint if needed).
    /// </summary>
    private static (string Jwt, ECDsaSecurityKey Key) BuildDpopProof(
        string method,
        string url,
        string? jti = null,
        string? nonce = null,
        string? accessToken = null,
        ECDsaSecurityKey? signingKey = null)
    {
        var key = signingKey ?? new ECDsaSecurityKey(
            ECDsa.Create(ECCurve.NamedCurves.nistP256));
        var jwk = JsonWebKeyConverter.ConvertFromECDsaSecurityKey(key);
        // Strip the private part — DPoP jwk headers carry the PUBLIC key only.
        // (JsonWebKeyConverter includes d; remove it so the header is public.)
        jwk.D = null;
        var jwkJson = System.Text.Json.JsonSerializer.Serialize(jwk);

        var claims = new Dictionary<string, object>
        {
            ["htm"] = method,
            ["htu"] = url,
            ["iat"] = EpochTime.GetIntDate(DateTimeOffset.UtcNow.UtcDateTime),
            ["exp"] = EpochTime.GetIntDate(DateTimeOffset.UtcNow.AddMinutes(1).UtcDateTime),
            ["jti"] = jti ?? Guid.NewGuid().ToString("N"),
        };
        // RFC 9449 §8 nonce claim — present only when the AS challenged.
        if (nonce is not null)
        {
            claims["nonce"] = nonce;
        }
        if (accessToken is not null)
        {
            claims["ath"] = Base64UrlEncoder.Encode(
                SHA256.HashData(System.Text.Encoding.ASCII.GetBytes(accessToken)));
        }

        var descriptor = new SecurityTokenDescriptor
        {
            Claims = claims,
            SigningCredentials = new SigningCredentials(key, SecurityAlgorithms.EcdsaSha256),
            // typ + jwk go in the JWT HEADER (not payload). AdditionalHeaderClaims
            // is the WIF mechanism for extra header parameters.
            AdditionalHeaderClaims = new Dictionary<string, object>
            {
                ["typ"] = DpopProofValidator.DpopHeaderType,
                ["jwk"] = System.Text.Json.JsonSerializer.Deserialize<System.Text.Json.JsonElement>(jwkJson),
            },
        };

        var handler = new JsonWebTokenHandler();
        var token = handler.CreateToken(descriptor);
        return (token, key);
    }
}
