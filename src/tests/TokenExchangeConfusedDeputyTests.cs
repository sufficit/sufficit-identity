using System.Net;
using Sufficit.Identity.Tests.Infrastructure;
using Xunit;

namespace Sufficit.Identity.Tests;

/// <summary>
/// Pins what actually stops the RFC 8693 confused deputy.
/// </summary>
/// <remarks>
/// The 2026-08-30 evaluation claimed the provenance policy closed this, and an
/// adversarial review disputed it: the policy requires the subject token to
/// name exactly one authorized party but never compares that party to the
/// caller, and OpenIddict stamps exactly one party on every token it mints.
/// Neither position was proven at the endpoint, so this test settles it by
/// exercising the real flow.
/// <para>The question: can a client holding
/// <c>Permissions.GrantTypes.TokenExchange</c> exchange a token that was NOT
/// minted for it? <c>TokenExchangeClientId</c> is an audience of
/// <c>ScopeName</c> (see <see cref="TestDataSeeder"/>) but is not an audience
/// of the standard <c>openid</c> scope, which carries no resource — so a
/// subject token requested with <c>openid</c> alone is a token the exchange
/// client was never an intended recipient of.</para>
/// </remarks>
[Collection(StsCollection.Name)]
public sealed class TokenExchangeConfusedDeputyTests
{
    private readonly SufficitIdentityTestFactory _factory;

    public TokenExchangeConfusedDeputyTests(SufficitIdentityTestFactory factory)
        => _factory = factory;

    [Fact]
    public async Task Exchanging_a_token_the_caller_is_not_an_audience_of_is_rejected()
    {
        var client = _factory.CreateClient();

        // Subject token minted for the password client, scoped to `openid`
        // only: no resource, so the exchange client is not among its audiences.
        var (subjectStatus, subjectBody) = await client.PostFormAsync(
            "/connect/token",
            new Dictionary<string, string>
            {
                ["grant_type"] = "password",
                ["username"] = TestDataSeeder.DefaultUsername,
                ["password"] = TestDataSeeder.DefaultPassword,
                ["client_id"] = TestDataSeeder.PasswordClientId,
                ["client_secret"] = TestDataSeeder.PasswordClientSecret,
                ["scope"] = "openid",
            });
        Assert.Equal(HttpStatusCode.OK, subjectStatus);
        var subjectToken = subjectBody.GetProperty("access_token").GetString();
        Assert.False(string.IsNullOrEmpty(subjectToken));

        var (exchangeStatus, exchangeBody) = await client.PostFormAsync(
            "/connect/token",
            new Dictionary<string, string>
            {
                ["grant_type"] = "urn:ietf:params:oauth:grant-type:token-exchange",
                ["subject_token"] = subjectToken!,
                ["subject_token_type"] = "urn:ietf:params:oauth:token-type:access_token",
                ["client_id"] = TestDataSeeder.TokenExchangeClientId,
                ["client_secret"] = TestDataSeeder.TokenExchangeClientSecret,
            });

        // The delegation must not happen. Whichever layer refuses it — the
        // authorization server's own audience check or the Sufficit provenance
        // policy — the endpoint must not hand back a token.
        Assert.NotEqual(HttpStatusCode.OK, exchangeStatus);
        Assert.False(
            exchangeBody.TryGetProperty("access_token", out _),
            "A client that was never an audience of the subject token received "
            + "a delegated token — this is the RFC 8693 confused deputy.");
    }

    [Fact]
    public async Task Exchanging_a_token_minted_for_the_caller_still_works()
    {
        // The control: the same client, same flow, but a subject token whose
        // scope names it as a resource. Without this, the test above could pass
        // for the wrong reason (exchange broken outright).
        var client = _factory.CreateClient();

        var (subjectStatus, subjectBody) = await client.PostFormAsync(
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
        Assert.Equal(HttpStatusCode.OK, subjectStatus);

        var (exchangeStatus, _) = await client.PostFormAsync(
            "/connect/token",
            new Dictionary<string, string>
            {
                ["grant_type"] = "urn:ietf:params:oauth:grant-type:token-exchange",
                ["subject_token"] = subjectBody.GetProperty("access_token").GetString()!,
                ["subject_token_type"] = "urn:ietf:params:oauth:token-type:access_token",
                ["client_id"] = TestDataSeeder.TokenExchangeClientId,
                ["client_secret"] = TestDataSeeder.TokenExchangeClientSecret,
            });

        Assert.Equal(HttpStatusCode.OK, exchangeStatus);
    }
}
