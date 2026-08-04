using System.Net;
using System.Net.Http.Json;
using System.Security.Cryptography;
using System.Text.Json;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Tokens;
using Sufficit.Identity.STS;
using Sufficit.Identity.STS.SharedSignals;
using Sufficit.Identity.Tests.Infrastructure;
using Xunit;

namespace Sufficit.Identity.Tests;

public sealed class SharedSignalsTests
{
    [Fact]
    public async Task Session_revoked_SET_has_the_required_SSF_CAEP_shape()
    {
        using var key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var generator = new CaepEventGenerator(
            new SigningCredentials(
                new ECDsaSecurityKey(key), SecurityAlgorithms.EcdsaSha256),
            "https://sts.tests.local");

        var encoded = generator.GenerateSessionRevoked(
            "user-123", "session-456", "https://receiver.tests.local/events");
        var validation = await new JsonWebTokenHandler().ValidateTokenAsync(
            encoded,
            new TokenValidationParameters
            {
                ValidIssuer = "https://sts.tests.local/",
                ValidAudience = "https://receiver.tests.local/events",
                IssuerSigningKey = new ECDsaSecurityKey(key),
                ValidateIssuer = true,
                ValidateAudience = true,
                ValidateIssuerSigningKey = true,
                // SSF forbids exp, so receivers validate freshness/replay via
                // iat + jti according to their stream policy instead.
                ValidateLifetime = false,
            });
        Assert.True(validation.IsValid, validation.Exception?.Message);
        var jwt = new JsonWebTokenHandler().ReadJsonWebToken(encoded);

        Assert.Equal("secevent+jwt", jwt.Typ);
        Assert.Equal("https://sts.tests.local/", jwt.Issuer);
        Assert.Equal("https://receiver.tests.local/events", jwt.Audiences.Single());
        Assert.True(jwt.TryGetPayloadValue("iat", out long _));
        Assert.True(jwt.TryGetPayloadValue("jti", out string _));
        Assert.True(jwt.TryGetPayloadValue("txn", out string _));
        Assert.False(jwt.TryGetPayloadValue("sub", out string _));
        Assert.False(jwt.TryGetPayloadValue("exp", out long _));

        Assert.True(jwt.TryGetPayloadValue("sub_id", out JsonElement subId));
        Assert.Equal("complex", subId.GetProperty("format").GetString());
        Assert.Equal("user-123",
            subId.GetProperty("user").GetProperty("sub").GetString());
        Assert.Equal("session-456",
            subId.GetProperty("session").GetProperty("id").GetString());

        Assert.True(jwt.TryGetPayloadValue("events", out JsonElement events));
        var revoked = events.GetProperty(CaepEventGenerator.SessionRevokedEventType);
        Assert.True(revoked.GetProperty("event_timestamp").GetInt64() > 0);
    }

    [Fact]
    public async Task SSF_discovery_is_exposed_only_when_the_transmitter_is_enabled()
    {
        using var disabled = SufficitIdentityTestFactory.CreateIsolated(
            new Dictionary<string, string?>());
        await ((IAsyncLifetime)disabled).InitializeAsync();
        Assert.Equal(HttpStatusCode.NotFound,
            (await disabled.CreateClient().GetAsync(
                "/.well-known/ssf-configuration")).StatusCode);

        using var enabled = SufficitIdentityTestFactory.CreateIsolated(
            new Dictionary<string, string?>
            {
                ["Sufficit:Identity:SharedSignals:Enabled"] = "true",
            });
        await ((IAsyncLifetime)enabled).InitializeAsync();
        using var response = await enabled.CreateClient().GetAsync(
            "/.well-known/ssf-configuration");
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        Assert.Equal("application/json",
            response.Content.Headers.ContentType?.MediaType);
        var metadata = await response.Content.ReadFromJsonAsync<JsonElement>();
        Assert.Equal("1_0", metadata.GetProperty("spec_version").GetString());
        Assert.Equal("https://sts.tests.local/",
            metadata.GetProperty("issuer").GetString());
        Assert.Equal("urn:ietf:rfc:8935",
            metadata.GetProperty("delivery_methods_supported")[0].GetString());
        Assert.False(metadata.TryGetProperty("configuration_endpoint", out _));
    }

    [Fact]
    public async Task Push_dispatcher_posts_an_authenticated_signed_SET()
    {
        using var key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var generator = new CaepEventGenerator(
            new SigningCredentials(
                new ECDsaSecurityKey(key), SecurityAlgorithms.EcdsaSha256),
            "https://sts.tests.local");
        var options = new SharedSignalsOptions
        {
            Enabled = true,
            Receivers =
            {
                new SharedSignalsReceiverOptions
                {
                    Id = "receiver-a",
                    Audience = "https://receiver.tests.local/events",
                    Endpoint = "https://receiver.tests.local/push",
                    Authorization = "Bearer test-secret",
                },
            },
        };
        var capture = new CaptureHandler();
        var dispatcher = new SharedSignalsPushDispatcher(
            generator,
            options,
            new HttpClient(capture),
            NullLogger<SharedSignalsPushDispatcher>.Instance);

        await dispatcher.SessionRevokedAsync(
            "user-123", "session-456", CancellationToken.None);

        Assert.Equal("https://receiver.tests.local/push",
            capture.RequestUri?.AbsoluteUri);
        Assert.Equal("application/secevent+jwt", capture.ContentType);
        Assert.Equal("Bearer test-secret", capture.Authorization);
        var jwt = new JsonWebTokenHandler().ReadJsonWebToken(capture.Body!);
        Assert.Equal("https://receiver.tests.local/events", jwt.Audiences.Single());
        Assert.True(jwt.TryGetPayloadValue("events", out JsonElement events));
        Assert.True(events.TryGetProperty(
            CaepEventGenerator.SessionRevokedEventType, out _));
    }

    private sealed class CaptureHandler : HttpMessageHandler
    {
        public Uri? RequestUri { get; private set; }
        public string? ContentType { get; private set; }
        public string? Authorization { get; private set; }
        public string? Body { get; private set; }

        protected override async Task<HttpResponseMessage> SendAsync(
            HttpRequestMessage request,
            CancellationToken cancellationToken)
        {
            RequestUri = request.RequestUri;
            ContentType = request.Content?.Headers.ContentType?.MediaType;
            Authorization = request.Headers.GetValues("Authorization").Single();
            Body = await request.Content!.ReadAsStringAsync(cancellationToken);
            return new HttpResponseMessage(HttpStatusCode.Accepted);
        }
    }
}
