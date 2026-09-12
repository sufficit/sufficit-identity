using System.Net;
using System.Security.Claims;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.StaticAssets;
using Microsoft.AspNetCore.TestHost;
using Microsoft.Extensions.DependencyInjection;
using Sufficit.Identity.Server;
using Xunit;

namespace Sufficit.Identity.Tests;

/// <summary>
/// Static assets must not pay the per-request cookie validation, while every
/// other request, including ones with no matched endpoint (where OpenIddict
/// handles its protocol endpoints), still authenticates.
/// </summary>
public sealed class StaticAssetAuthenticationTests
{
    [Fact]
    public async Task Static_asset_skips_cookie_validation()
    {
        await using var host = await CreateHostAsync();
        using var client = await SignedInClientAsync(host);

        using var response = await client.GetAsync("/app.css");

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        Assert.Equal("anonymous", await response.Content.ReadAsStringAsync());
        Assert.Equal(0, host.Services.GetRequiredService<ValidationCounter>().Count);
    }

    [Fact]
    public async Task Regular_endpoint_still_validates_the_cookie()
    {
        await using var host = await CreateHostAsync();
        using var client = await SignedInClientAsync(host);

        using var response = await client.GetAsync("/page");

        Assert.Equal("authenticated", await response.Content.ReadAsStringAsync());
        Assert.Equal(1, host.Services.GetRequiredService<ValidationCounter>().Count);
    }

    [Fact]
    public async Task Request_without_endpoint_still_authenticates()
    {
        await using var host = await CreateHostAsync();
        using var client = await SignedInClientAsync(host);

        using var response = await client.GetAsync("/connect/unmatched");

        Assert.Equal(HttpStatusCode.NotFound, response.StatusCode);
        Assert.Equal(1, host.Services.GetRequiredService<ValidationCounter>().Count);
    }

    private static async Task<WebApplication> CreateHostAsync()
    {
        var builder = WebApplication.CreateBuilder();
        builder.WebHost.UseTestServer();
        builder.Services.AddSingleton<ValidationCounter>();
        builder.Services
            .AddAuthentication(CookieAuthenticationDefaults.AuthenticationScheme)
            .AddCookie(options => options.Events.OnValidatePrincipal = context =>
            {
                if (!context.HttpContext.Request.Path.StartsWithSegments("/signin"))
                {
                    context.HttpContext.RequestServices
                        .GetRequiredService<ValidationCounter>().Increment();
                }

                return Task.CompletedTask;
            });
        builder.Services.AddAuthorization();

        var app = builder.Build();
        app.UseRouting();
        app.UseAuthenticationExceptStaticAssets();
        app.UseAuthorization();

        app.MapGet("/signin", (HttpContext context) => context.SignInAsync(
            new ClaimsPrincipal(new ClaimsIdentity(
                [new Claim(ClaimTypes.NameIdentifier, "user")],
                CookieAuthenticationDefaults.AuthenticationScheme))));
        app.MapGet("/app.css", UserState)
            .WithMetadata(new StaticAssetDescriptor
            {
                Route = "app.css",
                AssetPath = "app.css",
            });
        app.MapGet("/page", UserState);

        await app.StartAsync();
        return app;
    }

    private static string UserState(HttpContext context) =>
        context.User.Identity?.IsAuthenticated == true ? "authenticated" : "anonymous";

    private static async Task<HttpClient> SignedInClientAsync(WebApplication host)
    {
        var client = host.GetTestClient();
        using var signIn = await client.GetAsync("/signin");
        signIn.EnsureSuccessStatusCode();
        var cookie = signIn.Headers.GetValues("Set-Cookie").Single().Split(';', 2)[0];
        client.DefaultRequestHeaders.Add("Cookie", cookie);
        host.Services.GetRequiredService<ValidationCounter>().Reset();
        return client;
    }

    private sealed class ValidationCounter
    {
        private int _count;

        public int Count => _count;

        public void Increment() => Interlocked.Increment(ref _count);

        public void Reset() => Interlocked.Exchange(ref _count, 0);
    }
}
