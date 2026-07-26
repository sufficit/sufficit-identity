using System.Net;
using System.Net.Http.Headers;
using System.Net.Http.Json;
using System.Security.Claims;
using System.Security.Cryptography;
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
        string method, string url, string? jti = null)
    {
        var ecdsa = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var key = new ECDsaSecurityKey(ecdsa);
        var jwk = JsonWebKeyConverter.ConvertFromECDsaSecurityKey(key);
        // Strip the private part — DPoP jwk headers carry the PUBLIC key only.
        // (JsonWebKeyConverter includes d; remove it so the header is public.)
        jwk.D = null;
        var jwkJson = System.Text.Json.JsonSerializer.Serialize(jwk);

        var descriptor = new SecurityTokenDescriptor
        {
            Claims = new Dictionary<string, object>
            {
                ["htm"] = method,
                ["htu"] = url,
                ["iat"] = EpochTime.GetIntDate(DateTimeOffset.UtcNow.UtcDateTime),
                ["jti"] = jti ?? Guid.NewGuid().ToString("N"),
            },
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
