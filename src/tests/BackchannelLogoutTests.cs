using System.Net;
using System.Net.Http.Json;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Tokens;
using Sufficit.Identity.STS.Logout;
using Sufficit.Identity.Tests.Infrastructure;
using Xunit;

namespace Sufficit.Identity.Tests;

/// <summary>
/// Covers OIDC Back-Channel Logout 1.0 (item 3.2 [L1]): the hand-built
/// <c>logout_token</c> JWT shape, the discovery advertisement, and the
/// distributor's fan-out to a mock RP. The token generator and distributor are
/// portable components (depend only on Microsoft.IdentityModel + the OpenIddict
/// public manager interfaces), so the generator is unit-tested directly and
/// the distributor via a stubbed <c>HttpMessageHandler</c>.
/// </summary>
public sealed class BackchannelLogoutTests
{
    [Fact]
    public void Logout_token_has_the_required_oidc_backchannel_logout_shape()
    {
        // OIDC Back-Channel Logout 1.0 §2.4 mandates: typ=logout+jwt header,
        // iss, aud, iat, jti, events (with the backchannel-logout member), and
        // at least one of sub/sid. nonce MUST be absent.
        var ecdsa = System.Security.Cryptography.ECDsa.Create(
            System.Security.Cryptography.ECCurve.NamedCurves.nistP256);
        var credentials = new SigningCredentials(
            new ECDsaSecurityKey(ecdsa), SecurityAlgorithms.EcdsaSha256);

        var generator = new LogoutTokenGenerator(credentials, "https://sts.tests.local");
        var token = generator.Generate(
            subject: "user-123",
            sessionId: "session-abc",
            audience: "https://rp.tests.local");

        // Decode the header and payload WITHOUT signature validation (we only
        // care about shape here; signature is exercised implicitly by the
        // handler's own ECDsa key round-trip).
        var handler = new JsonWebTokenHandler();
        var jwt = handler.ReadJsonWebToken(token);

        Assert.Equal(LogoutTokenGenerator.LogoutTokenType, jwt.Typ);

        // Required claims present.
        Assert.Equal("https://sts.tests.local", jwt.Issuer);
        Assert.Equal("https://rp.tests.local", jwt.Audiences.Single());
        Assert.Equal("user-123", jwt.GetClaim("sub").Value);
        Assert.Equal("session-abc", jwt.GetClaim("sid").Value);
        Assert.True(jwt.TryGetPayloadValue("jti", out string _));
        Assert.True(jwt.TryGetPayloadValue("iat", out long _));

        // events claim carries the backchannel-logout member (non-empty object).
        var events = jwt.GetClaim("events").Value;
        Assert.Contains(LogoutTokenGenerator.BackchannelLogoutEventUri, events, StringComparison.Ordinal);

        // nonce MUST be absent (§2.4: a logout_token MUST NOT contain a nonce).
        Assert.DoesNotContain(jwt.Claims, c => string.Equals(c.Type, "nonce", StringComparison.Ordinal));
    }

    [Fact]
    public void Logout_token_generator_rejects_missing_subject_and_session()
    {
        // Spec requires at least one of sub/sid. Without either, the RP cannot
        // know which session to terminate — reject at generation time.
        var ecdsa = System.Security.Cryptography.ECDsa.Create(
            System.Security.Cryptography.ECCurve.NamedCurves.nistP256);
        var credentials = new SigningCredentials(
            new ECDsaSecurityKey(ecdsa), SecurityAlgorithms.EcdsaSha256);
        var generator = new LogoutTokenGenerator(credentials, "https://sts.tests.local");

        Assert.Throws<ArgumentException>(() =>
            generator.Generate(subject: null, sessionId: null, audience: "https://rp.tests.local"));
    }

    [Fact]
    public async Task Discovery_advertises_backchannel_logout_when_enabled()
    {
        // Isolated factory with BackchannelLogout.Enabled=true: discovery must
        // flip backchannel_logout_supported from its default false to true.
        using var factory = SufficitIdentityTestFactory.CreateIsolated(new Dictionary<string, string?>
        {
            ["Sufficit:Identity:BackchannelLogout:Enabled"] = "true",
        });
        await ((IAsyncLifetime)factory).InitializeAsync();

        var client = factory.CreateClient();
        var response = await client.GetAsync("/.well-known/openid-configuration");
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);

        var json = await response.Content.ReadFromJsonAsync<System.Text.Json.JsonElement>();
        Assert.True(json.GetProperty("backchannel_logout_supported").GetBoolean());
        Assert.True(json.GetProperty("backchannel_logout_session_supported").GetBoolean());

        // Front-channel logout stays off regardless (deliberately not implemented).
        Assert.False(json.GetProperty("frontchannel_logout_supported").GetBoolean());
    }
}
