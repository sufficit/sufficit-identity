using System.Net;
using System.Text;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Caching.Distributed;
using Microsoft.Extensions.Caching.Memory;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;
using Sufficit.Identity.AspNetCore.Authentication.OAuth2Introspection;
using Xunit;

namespace Sufficit.Identity.Tests;

/// <summary>Package Sufficit.Identity.AspNetCore.Authentication.OAuth2Introspection.</summary>
public sealed class OAuth2IntrospectionPackageTests
{
    private sealed class Endpoint(Func<int, HttpResponseMessage> answer, TimeSpan delay = default) : HttpMessageHandler
    {
        public int Calls;
        public string? LastBody;
        protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken ct)
        {
            var n = Interlocked.Increment(ref Calls);
            LastBody = await request.Content!.ReadAsStringAsync(ct);
            if (delay > TimeSpan.Zero) await Task.Delay(delay, ct);
            return answer(n);
        }
    }

    private sealed class Factory(HttpMessageHandler handler) : IHttpClientFactory
    {
        public HttpClient CreateClient(string name) => new(handler, disposeHandler: false);
    }

    private sealed class BrokenCache : IDistributedCache
    {
        public byte[]? Get(string key) => throw new InvalidOperationException();
        public Task<byte[]?> GetAsync(string key, CancellationToken token = default) => throw new InvalidOperationException("cache down");
        public void Refresh(string key) { }
        public Task RefreshAsync(string key, CancellationToken token = default) => Task.CompletedTask;
        public void Remove(string key) { }
        public Task RemoveAsync(string key, CancellationToken token = default) => Task.CompletedTask;
        public void Set(string key, byte[] value, DistributedCacheEntryOptions options) { }
        public Task SetAsync(string key, byte[] value, DistributedCacheEntryOptions options, CancellationToken token = default) => throw new InvalidOperationException("cache down");
    }

    private static HttpResponseMessage Json(string body, HttpStatusCode status = HttpStatusCode.OK)
        => new(status) { Content = new StringContent(body, Encoding.UTF8, "application/json") };

    private static string Active(long? exp = null)
        => $"{{\"active\":true,\"sub\":\"u1\",\"name\":\"Ana\",\"scope\":\"fleet.api openid\",\"aud\":[\"a\",\"b\"],\"exp\":{exp ?? DateTimeOffset.UtcNow.AddHours(1).ToUnixTimeSeconds()}}}";

    private static OAuth2IntrospectionOptions Options(bool cache = true) => new()
    {
        Authority = "https://identity.example/",
        ClientId = "api",
        ClientSecret = "s3cret",
        EnableCaching = cache,
        CacheDuration = TimeSpan.FromMinutes(1),
        CacheKeyPrefix = "t:",
    };

    private static OAuth2IntrospectionClient Client(HttpMessageHandler endpoint, IDistributedCache? cache = null)
        => new(new Factory(endpoint), cache ?? new MemoryDistributedCache(Microsoft.Extensions.Options.Options.Create(new MemoryDistributedCacheOptions())),
            NullLogger<OAuth2IntrospectionClient>.Instance);

    [Fact]
    public async Task Active_result_is_cached_and_endpoint_called_once()
    {
        var endpoint = new Endpoint(_ => Json(Active()));
        var client = Client(endpoint);
        var first = await client.IntrospectAsync("tok", Options());
        var second = await client.IntrospectAsync("tok", Options());
        Assert.True(first.IsActive);
        Assert.False(first.FromCache);
        Assert.True(second.FromCache);
        Assert.Equal(1, endpoint.Calls);
        Assert.Contains("client_id=api", endpoint.LastBody);
        Assert.Contains("token_type_hint=access_token", endpoint.LastBody);
    }

    [Fact]
    public async Task Without_caching_every_call_reaches_endpoint()
    {
        var endpoint = new Endpoint(_ => Json(Active()));
        var client = Client(endpoint);
        await client.IntrospectAsync("tok", Options(cache: false));
        await client.IntrospectAsync("tok", Options(cache: false));
        Assert.Equal(2, endpoint.Calls);
    }

    [Fact]
    public async Task Inactive_result_is_never_cached()
    {
        var endpoint = new Endpoint(_ => Json("{\"active\":false}"));
        var client = Client(endpoint);
        Assert.False((await client.IntrospectAsync("bad", Options())).IsActive);
        Assert.False((await client.IntrospectAsync("bad", Options())).IsActive);
        Assert.Equal(2, endpoint.Calls);
    }

    [Fact]
    public async Task Concurrent_lookups_of_one_token_share_one_call()
    {
        var endpoint = new Endpoint(_ => Json(Active()), TimeSpan.FromMilliseconds(200));
        var client = Client(endpoint);
        var results = await Task.WhenAll(Enumerable.Range(0, 32).Select(_ => client.IntrospectAsync("tok", Options(cache: false))));
        Assert.All(results, r => Assert.True(r.IsActive));
        Assert.Equal(1, endpoint.Calls);
    }

    [Fact]
    public async Task Expired_cache_entry_is_not_served()
    {
        var endpoint = new Endpoint(_ => Json(Active(DateTimeOffset.UtcNow.AddSeconds(1).ToUnixTimeSeconds())));
        var client = Client(endpoint);
        await client.IntrospectAsync("tok", Options());
        await Task.Delay(TimeSpan.FromSeconds(2.1));
        await client.IntrospectAsync("tok", Options());
        Assert.Equal(2, endpoint.Calls);
    }

    [Theory]
    [InlineData(HttpStatusCode.InternalServerError)]
    [InlineData(HttpStatusCode.TooManyRequests)]
    [InlineData(HttpStatusCode.Unauthorized)]
    [InlineData(HttpStatusCode.BadGateway)]
    public async Task Endpoint_failure_is_unavailable_not_a_verdict(HttpStatusCode status)
    {
        var endpoint = new Endpoint(_ => Json("{}", status));
        var error = await Assert.ThrowsAsync<IntrospectionUnavailableException>(() => Client(endpoint).IntrospectAsync("tok", Options()));
        Assert.Equal(status, error.StatusCode);
    }

    [Fact]
    public async Task Non_rfc7662_body_is_unavailable()
    {
        var endpoint = new Endpoint(_ => Json("<html>proxy</html>"));
        await Assert.ThrowsAsync<IntrospectionUnavailableException>(() => Client(endpoint).IntrospectAsync("tok", Options()));
    }

    [Fact]
    public async Task Failure_is_not_cached_and_next_call_recovers()
    {
        var endpoint = new Endpoint(n => n == 1 ? Json("{}", HttpStatusCode.ServiceUnavailable) : Json(Active()));
        var client = Client(endpoint);
        await Assert.ThrowsAsync<IntrospectionUnavailableException>(() => client.IntrospectAsync("tok", Options()));
        Assert.True((await client.IntrospectAsync("tok", Options())).IsActive);
    }

    [Fact]
    public async Task Broken_cache_degrades_to_endpoint()
    {
        var endpoint = new Endpoint(_ => Json(Active()));
        Assert.True((await Client(endpoint, new BrokenCache()).IntrospectAsync("tok", Options())).IsActive);
    }

    [Fact]
    public void Cache_key_never_contains_the_token()
    {
        var key = OAuth2IntrospectionOptions.DefaultCacheKey(Options(), "secret-token");
        Assert.StartsWith("t:", key);
        Assert.DoesNotContain("secret-token", key);
    }

    [Fact]
    public async Task Result_exposes_scope_and_audience_values()
    {
        var result = await Client(new Endpoint(_ => Json(Active()))).IntrospectAsync("tok", Options());
        Assert.Equal(["fleet.api", "openid"], result.Values("scope"));
        Assert.Equal(["a", "b"], result.Values("aud"));
    }

    private static async Task<HttpContext> Authenticate(HttpMessageHandler endpoint, string? authorization)
    {
        var services = new ServiceCollection().AddLogging();
        services.AddAuthentication(OAuth2IntrospectionDefaults.AuthenticationScheme).AddOAuth2Introspection(o =>
        {
            o.Authority = "https://identity.example";
            o.ClientId = "api";
            o.EnableCaching = true;
        });
        services.AddSingleton<IHttpClientFactory>(new Factory(endpoint));
        var provider = services.BuildServiceProvider();
        var context = new DefaultHttpContext { RequestServices = provider };
        if (authorization is not null) context.Request.Headers.Authorization = authorization;
        var result = await context.AuthenticateAsync();
        if (result.Succeeded) context.User = result.Principal!;
        else await context.ChallengeAsync();
        return context;
    }

    [Fact]
    public async Task Handler_builds_principal_from_active_token()
    {
        var context = await Authenticate(new Endpoint(_ => Json(Active())), "Bearer tok");
        Assert.True(context.User.Identity!.IsAuthenticated);
        Assert.Equal("Ana", context.User.Identity.Name);
        Assert.Contains(context.User.Claims, c => c.Type == "scope" && c.Value == "fleet.api");
    }

    [Fact]
    public async Task Handler_answers_401_for_inactive_token()
    {
        var context = await Authenticate(new Endpoint(_ => Json("{\"active\":false}")), "Bearer bad");
        Assert.Equal(401, context.Response.StatusCode);
        Assert.Contains("invalid_token", context.Response.Headers.WWWAuthenticate.ToString());
    }

    [Fact]
    public async Task Handler_answers_503_when_identity_fails()
    {
        var context = await Authenticate(new Endpoint(_ => Json("{}", HttpStatusCode.InternalServerError)), "Bearer tok");
        Assert.Equal(503, context.Response.StatusCode);
        Assert.Equal("5", context.Response.Headers.RetryAfter.ToString());
        Assert.Empty(context.Response.Headers.WWWAuthenticate.ToString());
    }

    [Fact]
    public async Task Handler_without_token_does_not_call_endpoint()
    {
        var endpoint = new Endpoint(_ => Json(Active()));
        var context = await Authenticate(endpoint, null);
        Assert.Equal(401, context.Response.StatusCode);
        Assert.Equal(0, endpoint.Calls);
    }

    [Fact]
    public void Options_require_endpoint_and_client()
    {
        Assert.Throws<InvalidOperationException>(() => new OAuth2IntrospectionOptions { ClientId = "api" }.Validate());
        Assert.Throws<InvalidOperationException>(() => new OAuth2IntrospectionOptions { Authority = "https://x" }.Validate());
        Assert.Equal("https://x/connect/introspect", new OAuth2IntrospectionOptions { Authority = "https://x/", ClientId = "a" }.ResolveEndpoint());
    }
}
