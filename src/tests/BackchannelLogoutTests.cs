using System.Net;
using System.Net.Http.Json;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.WebUtilities;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Tokens;
using OpenIddict.Abstractions;
using Sufficit.Identity.Core.Entities;
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
            audience: "rp-client-id");

        // Decode the header and payload WITHOUT signature validation (we only
        // care about shape here; signature is exercised implicitly by the
        // handler's own ECDsa key round-trip).
        var handler = new JsonWebTokenHandler();
        var jwt = handler.ReadJsonWebToken(token);

        Assert.Equal(LogoutTokenGenerator.LogoutTokenType, jwt.Typ);

        // Required claims present.
        Assert.Equal("https://sts.tests.local", jwt.Issuer);
        Assert.Equal("rp-client-id", jwt.Audiences.Single());
        Assert.Equal("user-123", jwt.GetClaim("sub").Value);
        Assert.Equal("session-abc", jwt.GetClaim("sid").Value);
        Assert.True(jwt.TryGetPayloadValue("jti", out string _));
        Assert.True(jwt.TryGetPayloadValue("iat", out long _));
        Assert.True(jwt.TryGetPayloadValue("exp", out long _));

        // events is a JSON object (not a JSON-looking string) carrying the
        // backchannel-logout member.
        Assert.True(jwt.TryGetPayloadValue(
            "events", out System.Text.Json.JsonElement events));
        Assert.Equal(System.Text.Json.JsonValueKind.Object, events.ValueKind);
        Assert.True(events.TryGetProperty(
            LogoutTokenGenerator.BackchannelLogoutEventUri, out var logoutEvent));
        Assert.Equal(System.Text.Json.JsonValueKind.Object, logoutEvent.ValueKind);

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

        Assert.True(json.GetProperty("frontchannel_logout_supported").GetBoolean());
        Assert.True(json.GetProperty("frontchannel_logout_session_supported").GetBoolean());
    }

    [Fact]
    public async Task Discovery_does_not_advertise_logout_dispatchers_when_disabled()
    {
        using var factory = SufficitIdentityTestFactory.CreateIsolated(new Dictionary<string, string?>
        {
            ["Sufficit:Identity:BackchannelLogout:Enabled"] = "false",
            ["Sufficit:Identity:FrontchannelLogout:Enabled"] = "false",
        });
        await ((IAsyncLifetime)factory).InitializeAsync();

        var json = await factory.CreateClient()
            .GetFromJsonAsync<System.Text.Json.JsonElement>("/.well-known/openid-configuration");

        Assert.False(json.GetProperty("backchannel_logout_supported").GetBoolean());
        Assert.False(json.GetProperty("frontchannel_logout_supported").GetBoolean());
    }

    [Fact]
    public async Task Distributor_posts_a_logout_token_addressed_to_the_registered_client_id()
    {
        using var factory = SufficitIdentityTestFactory.CreateIsolated(
            new Dictionary<string, string?>());
        await ((IAsyncLifetime)factory).InitializeAsync();
        await using var scope = factory.Services.CreateAsyncScope();

        var users = scope.ServiceProvider.GetRequiredService<UserManager<ApplicationUser>>();
        var applications = scope.ServiceProvider
            .GetRequiredService<IOpenIddictApplicationManager>();
        var authorizations = scope.ServiceProvider
            .GetRequiredService<IOpenIddictAuthorizationManager>();
        var user = await users.FindByNameAsync(TestDataSeeder.DefaultUsername)
            ?? throw new InvalidOperationException("Seeded user missing.");

        const string clientId = "backchannel-test-client";
        var applicationDescriptor = new OpenIddictApplicationDescriptor
        {
            ClientId = clientId,
            ClientType = OpenIddictConstants.ClientTypes.Public,
            ConsentType = OpenIddictConstants.ConsentTypes.Implicit,
        };
        applicationDescriptor.Settings["backchannel_logout_uri"] =
            "https://rp.tests.local/backchannel-logout";
        applicationDescriptor.Settings["backchannel_logout_session_required"] = "true";
        var application = await applications.CreateAsync(applicationDescriptor);
        var applicationId = await applications.GetIdAsync(application)
            ?? throw new InvalidOperationException("Application id missing.");

        await authorizations.CreateAsync(new OpenIddictAuthorizationDescriptor
        {
            ApplicationId = applicationId,
            CreationDate = DateTimeOffset.UtcNow,
            Status = OpenIddictConstants.Statuses.Valid,
            Subject = user.Id,
            Type = OpenIddictConstants.AuthorizationTypes.Permanent,
        });

        var ecdsa = System.Security.Cryptography.ECDsa.Create(
            System.Security.Cryptography.ECCurve.NamedCurves.nistP256);
        var generator = new LogoutTokenGenerator(
            new SigningCredentials(
                new ECDsaSecurityKey(ecdsa),
                SecurityAlgorithms.EcdsaSha256),
            "https://sts.tests.local");
        var handler = new CapturingLogoutHandler();
        var dispatcher = new BackchannelLogoutDistributor(
            authorizations,
            applications,
            generator,
            new HttpClient(handler),
            NullLogger<BackchannelLogoutDistributor>.Instance);

        await dispatcher.DistributeAsync(
            user.Id,
            sessionId: "session-123",
            CancellationToken.None);

        Assert.Equal(
            "https://rp.tests.local/backchannel-logout",
            handler.RequestUri?.AbsoluteUri);
        var values = QueryHelpers.ParseQuery(handler.Body ?? string.Empty);
        var token = values["logout_token"].ToString();
        Assert.False(string.IsNullOrWhiteSpace(token));
        var logoutToken = new JsonWebTokenHandler().ReadJsonWebToken(token);
        Assert.Equal(clientId, logoutToken.Audiences.Single());
        Assert.Equal("session-123", logoutToken.GetClaim("sid").Value);
    }

    private sealed class CapturingLogoutHandler : HttpMessageHandler
    {
        public Uri? RequestUri { get; private set; }
        public string? Body { get; private set; }

        protected override async Task<HttpResponseMessage> SendAsync(
            HttpRequestMessage request,
            CancellationToken cancellationToken)
        {
            RequestUri = request.RequestUri;
            Body = request.Content is null
                ? null
                : await request.Content.ReadAsStringAsync(cancellationToken);
            return new HttpResponseMessage(HttpStatusCode.OK);
        }
    }
}
