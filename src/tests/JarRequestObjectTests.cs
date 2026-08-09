using System.Net;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Microsoft.IdentityModel.Tokens;
using OpenIddict.Abstractions;
using Sufficit.Identity.STS;
using Sufficit.Identity.STS.Jar;
using Xunit;

namespace Sufficit.Identity.Tests;

public sealed class JarRequestObjectTests
{
    [Theory]
    [InlineData("http://keys.example/jwks.json")]
    [InlineData("https://127.0.0.1/jwks.json")]
    [InlineData("https://10.1.2.3/jwks.json")]
    [InlineData("https://user@keys.example/jwks.json")]
    [InlineData("https://keys.example/jwks.json#fragment")]
    public void Remote_jwks_rejects_non_public_https_uris(string value) =>
        Assert.Throws<HttpRequestException>(() =>
            RemoteJwksProvider.ValidateUri(new Uri(value)));

    [Fact]
    public async Task Remote_jwks_refreshes_immediately_when_kid_rotates()
    {
        var handler = new SequenceHandler(
            _ => JwksResponse(CreatePublicEcJwk("key-1")),
            _ => JwksResponse(CreatePublicEcJwk("key-2")));
        var provider = CreateRemoteProvider(handler);
        var uri = new Uri("https://keys.example/jwks.json");

        var first = await provider.GetKeysAsync(uri, "key-1", default);
        var rotated = await provider.GetKeysAsync(uri, "key-2", default);

        Assert.Single(first);
        Assert.Single(rotated);
        Assert.Equal("key-2", rotated[0].KeyId);
        Assert.Equal(2, handler.RequestCount);
    }

    [Fact]
    public async Task Remote_jwks_uses_stale_cache_only_for_a_known_kid()
    {
        var handler = new SequenceHandler(
            _ => JwksResponse(CreatePublicEcJwk("known")),
            _ => new HttpResponseMessage(HttpStatusCode.ServiceUnavailable),
            _ => new HttpResponseMessage(HttpStatusCode.ServiceUnavailable));
        var time = new MutableTimeProvider(
            new DateTimeOffset(2026, 8, 9, 12, 0, 0, TimeSpan.Zero));
        var provider = CreateRemoteProvider(handler, time);
        var uri = new Uri("https://keys.example/jwks.json");

        await provider.GetKeysAsync(uri, "known", default);
        time.Advance(TimeSpan.FromSeconds(11));

        var stale = await provider.GetKeysAsync(uri, "known", default);
        Assert.Single(stale);
        await Assert.ThrowsAsync<HttpRequestException>(() =>
            provider.GetKeysAsync(uri, "unknown", default));
    }

    [Fact]
    public async Task Remote_jwks_rejects_redirects_oversized_and_private_key_sets()
    {
        var redirect = CreateRemoteProvider(new SequenceHandler(_ => new HttpResponseMessage(
            HttpStatusCode.Redirect)
        {
            Headers = { Location = new Uri("https://other.example/jwks.json") },
        }));
        await Assert.ThrowsAsync<HttpRequestException>(() =>
            redirect.GetKeysAsync(
                new Uri("https://keys.example/redirect"), "key", default));

        var oversized = CreateRemoteProvider(new SequenceHandler(_ =>
            new HttpResponseMessage(HttpStatusCode.OK)
            {
                Content = new ByteArrayContent(new byte[2049]),
            }), maxBytes: 2048);
        await Assert.ThrowsAsync<HttpRequestException>(() =>
            oversized.GetKeysAsync(
                new Uri("https://keys.example/large"), "key", default));

        var publicKey = CreatePublicEcJwk("private");
        var privateSet = publicKey.TrimEnd('}') + ",\"d\":\"AA\"}";
        var privateProvider = CreateRemoteProvider(new SequenceHandler(
            _ => JwksResponse(privateSet)));
        await Assert.ThrowsAsync<JsonException>(() =>
            privateProvider.GetKeysAsync(
                new Uri("https://keys.example/private"), "private", default));
    }

    [Fact]
    public async Task Remote_jwks_requires_kid_when_the_set_is_ambiguous()
    {
        var provider = CreateRemoteProvider(new SequenceHandler(_ =>
            JwksResponse(
                CreatePublicEcJwk("key-1"),
                CreatePublicEcJwk("key-2"))));

        var keys = await provider.GetKeysAsync(
            new Uri("https://keys.example/jwks.json"), null, default);

        Assert.Empty(keys);
    }

    [Fact]
    public async Task Remote_jwks_cache_is_bounded()
    {
        var handler = new SequenceHandler(
            _ => JwksResponse(CreatePublicEcJwk("key")),
            _ => JwksResponse(CreatePublicEcJwk("key")),
            _ => JwksResponse(CreatePublicEcJwk("key")));
        var provider = CreateRemoteProvider(handler, maxCacheEntries: 2);

        for (var index = 0; index < 3; index++)
        {
            await provider.GetKeysAsync(
                new Uri($"https://keys-{index}.example/jwks.json"),
                "key",
                default);
        }

        Assert.Equal(2, provider.CacheEntryCount);
    }

    [Fact]
    public void Signed_payload_replaces_outer_parameters_and_preserves_json_shapes()
    {
        var request = new OpenIddictRequest
        {
            ClientId = "jar-client",
            Scope = "identity.management",
            Prompt = "none",
            MaxAge = 3600,
            LoginHint = "injected@example.invalid",
            AcrValues = "urn:injected:acr",
        };
        request.SetParameter("resource", "https://injected.example.invalid");
        request.SetParameter("unknown_extension", "injected");
        request.SetParameter(OpenIddictConstants.Parameters.Request, "signed.jwt");

        using var document = JsonDocument.Parse(
            """
            {
              "iss": "jar-client",
              "aud": "https://identity.example.invalid",
              "exp": 1786300000,
              "iat": 1786299940,
              "jti": "signed-request-id",
              "client_id": "jar-client",
              "response_type": "code",
              "redirect_uri": "https://client.example.invalid/callback",
              "scope": "openid profile",
              "claims": {
                "id_token": {
                  "acr": { "essential": true }
                }
              },
              "authorization_details": [
                { "type": "payment", "actions": ["read", "approve"] }
              ]
            }
            """);

        var replaced = JarExtractor.TryReplaceWithSignedParameters(
            request,
            document.RootElement,
            "jar-client",
            out var error);

        Assert.True(replaced, error);
        Assert.Equal("jar-client", request.ClientId);
        Assert.Equal("code", request.ResponseType);
        Assert.Equal("openid profile", request.Scope);
        Assert.Equal(
            "https://client.example.invalid/callback",
            request.RedirectUri);
        foreach (var outerOnly in new[]
                 {
                     "resource",
                     "prompt",
                     "max_age",
                     "login_hint",
                     "acr_values",
                     "unknown_extension",
                     OpenIddictConstants.Parameters.Request,
                 })
        {
            Assert.False(request.HasParameter(outerOnly));
        }

        var claims = (JsonElement?)request.GetParameter("claims");
        var authorizationDetails =
            (JsonElement?)request.GetParameter("authorization_details");
        Assert.Equal(JsonValueKind.Object, claims?.ValueKind);
        Assert.True(claims?.GetProperty("id_token")
            .GetProperty("acr")
            .GetProperty("essential")
            .GetBoolean());
        Assert.Equal(JsonValueKind.Array, authorizationDetails?.ValueKind);
        Assert.Equal(
            "approve",
            authorizationDetails?[0]
                .GetProperty("actions")[1]
                .GetString());
    }

    [Theory]
    [InlineData("request")]
    [InlineData("request_uri")]
    public void Signed_payload_rejects_nested_request_carriers(string carrier)
    {
        var request = new OpenIddictRequest { ClientId = "jar-client" };
        using var document = JsonDocument.Parse(
            $$"""
            {
              "client_id": "jar-client",
              "response_type": "code",
              "{{carrier}}": "nested"
            }
            """);

        var replaced = JarExtractor.TryReplaceWithSignedParameters(
            request,
            document.RootElement,
            "jar-client",
            out var error);

        Assert.False(replaced);
        Assert.Contains("cannot contain", error, StringComparison.Ordinal);
    }

    private static RemoteJwksProvider CreateRemoteProvider(
        HttpMessageHandler handler,
        TimeProvider? timeProvider = null,
        int maxBytes = 65_536,
        int maxCacheEntries = 256) =>
        new(
            new HttpClient(handler),
            new JarOptions
            {
                RemoteJwksMaxBytes = maxBytes,
                RemoteJwksTimeoutSeconds = 3,
                RemoteJwksCacheSeconds = 10,
                RemoteJwksStaleSeconds = 30,
                RemoteJwksMaxCacheEntries = maxCacheEntries,
            },
            timeProvider);

    private static HttpResponseMessage JwksResponse(params string[] keys) =>
        new(HttpStatusCode.OK)
        {
            Content = new StringContent(
                $$"""{"keys":[{{string.Join(',', keys)}}]}""",
                Encoding.UTF8,
                "application/jwk-set+json"),
        };

    private static string CreatePublicEcJwk(string kid)
    {
        using var algorithm = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var parameters = algorithm.ExportParameters(false);
        return JsonSerializer.Serialize(new Dictionary<string, object>
        {
            ["kty"] = "EC",
            ["crv"] = "P-256",
            ["x"] = Base64UrlEncoder.Encode(parameters.Q.X),
            ["y"] = Base64UrlEncoder.Encode(parameters.Q.Y),
            ["kid"] = kid,
            ["use"] = "sig",
            ["alg"] = "ES256",
        });
    }

    private sealed class SequenceHandler(
        params Func<HttpRequestMessage, HttpResponseMessage>[] responses)
        : HttpMessageHandler
    {
        private int _index;

        public int RequestCount => _index;

        protected override Task<HttpResponseMessage> SendAsync(
            HttpRequestMessage request,
            CancellationToken cancellationToken)
        {
            var index = Interlocked.Increment(ref _index) - 1;
            if (index >= responses.Length)
            {
                throw new InvalidOperationException("No HTTP response was configured.");
            }
            return Task.FromResult(responses[index](request));
        }
    }

    private sealed class MutableTimeProvider(DateTimeOffset utcNow) : TimeProvider
    {
        private DateTimeOffset _utcNow = utcNow;

        public override DateTimeOffset GetUtcNow() => _utcNow;

        public void Advance(TimeSpan elapsed) => _utcNow += elapsed;
    }
}
