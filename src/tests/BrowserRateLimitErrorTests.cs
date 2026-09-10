using System.Net;
using System.Text.Json;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.TestHost;
using Microsoft.Extensions.DependencyInjection;
using Sufficit.Identity.Server;
using Sufficit.Identity.STS;
using Xunit;

namespace Sufficit.Identity.Tests;

public sealed class BrowserRateLimitErrorTests
{
    private static async Task<WebApplication> StartAsync(bool embedded = true)
    {
        var builder = WebApplication.CreateBuilder();
        builder.WebHost.UseTestServer();
        builder.Services.AddRazorComponents();
        builder.Services.AddLocalization();
        if (embedded) builder.Services.AddSingleton<BrowserRateLimitErrors>();
        builder.Services.AddSufficitIdentityRateLimiter(new RateLimitOptions
        {
            PermitLimit = 1, WindowSeconds = 120,
            IntrospectionPermitLimit = 1, IntrospectionWindowSeconds = 120,
            PushedAuthorizationPermitLimit = 1, PushedAuthorizationWindowSeconds = 120,
            DeviceInformationPermitLimit = 1, DeviceInformationWindowSeconds = 120
        }, "api");
        var app = builder.Build();
        app.UseRouting();
        app.UseRateLimiter();
        app.MapMethods("/{**path}", ["GET", "POST"], () => Results.Ok());
        await app.StartAsync();
        return app;
    }

    private static HttpRequestMessage Navigation(string path, string language)
    {
        var request = new HttpRequestMessage(HttpMethod.Post, path);
        request.Headers.TryAddWithoutValidation("Accept", "text/html,application/xhtml+xml,*/*;q=0.8");
        request.Headers.TryAddWithoutValidation("Accept-Language", language);
        request.Headers.TryAddWithoutValidation("Sec-Fetch-Mode", "navigate");
        request.Headers.TryAddWithoutValidation("Sec-Fetch-Dest", "document");
        return request;
    }

    [Theory]
    [InlineData("pt-BR,pt;q=0.9,en;q=0.8", "pt-BR", "Aguarde um pouco")]
    [InlineData("en-GB,en;q=0.9", "en-US", "Please wait")]
    [InlineData("pt;q=0.3,en;q=0.8", "en-US", "Please wait")]
    [InlineData("en;q=0,pt;q=0.5", "pt-BR", "Aguarde um pouco")]
    [InlineData("fr", "pt-BR", "Aguarde um pouco")]
    public async Task Interactive_429_uses_browser_language_and_existing_safe_page(
        string language, string culture, string title)
    {
        await using var app = await StartAsync();
        using var client = app.GetTestClient();
        using var first = await client.PostAsync("/connect/device", null);
        Assert.Equal(HttpStatusCode.OK, first.StatusCode);
        using var request = Navigation("/connect/device?user_code=SECRET&returnUrl=https://evil.invalid&error_description=INJECTED", language);
        using var response = await client.SendAsync(request);
        var html = await response.Content.ReadAsStringAsync();
        Assert.Equal(HttpStatusCode.TooManyRequests, response.StatusCode);
        Assert.Equal("text/html", response.Content.Headers.ContentType?.MediaType);
        Assert.Equal(culture, Assert.Single(response.Content.Headers.ContentLanguage));
        Assert.Contains($"lang=\"{culture}\"", html);
        Assert.Contains(title, html);
        Assert.Contains("authorization-error.css", html);
        Assert.Contains("href=\"/\"", html);
        var seconds = (int)response.Headers.RetryAfter!.Delta!.Value.TotalSeconds;
        Assert.InRange(seconds, 1, 120);
        Assert.Contains(seconds.ToString(), html);
        Assert.True(response.Headers.CacheControl!.NoStore);
        Assert.Equal("no-referrer", Assert.Single(response.Headers.GetValues("Referrer-Policy")));
        foreach (var forbidden in new[] { "SECRET", "evil.invalid", "INJECTED", "<script", "<form", "temporarily_unavailable" })
            Assert.DoesNotContain(forbidden, html, StringComparison.OrdinalIgnoreCase);
        if (Environment.GetEnvironmentVariable("SUFFICIT_AUTH_PREVIEW_DIR") is { Length: > 0 } directory)
        {
            Directory.CreateDirectory(directory);
            await File.WriteAllTextAsync(Path.Combine(directory, $"rate-limit-{culture}.html"), html);
        }
    }

    [Theory]
    [InlineData("/connect/token")]
    [InlineData("/connect/token/mtls")]
    [InlineData("/connect/introspect")]
    [InlineData("/connect/par")]
    [InlineData("/connect/register")]
    [InlineData("/connect/deviceauthorization")]
    [InlineData("/account/passkeys/assertion")]
    public async Task Protocol_and_passkey_apis_keep_json_even_with_navigation_headers(string path)
    {
        await using var app = await StartAsync();
        using var client = app.GetTestClient();
        using var first = await client.PostAsync(path, null);
        using var request = Navigation(path, "en");
        using var response = await client.SendAsync(request);
        Assert.Equal(HttpStatusCode.TooManyRequests, response.StatusCode);
        Assert.Equal("application/json", response.Content.Headers.ContentType?.MediaType);
        using var json = JsonDocument.Parse(await response.Content.ReadAsStringAsync());
        Assert.Equal(path.StartsWith("/connect/") ? "temporarily_unavailable" : "rate_limit_exceeded",
            json.RootElement.GetProperty("error").GetString());
    }

    [Theory]
    [InlineData("application/json", null, null, null)]
    [InlineData("*/*", null, null, null)]
    [InlineData("text/html,application/json", "navigate", "document", null)]
    [InlineData("text/html", "cors", "empty", null)]
    [InlineData("text/html", "navigate", "iframe", null)]
    [InlineData("text/html", "navigate", "document", "XMLHttpRequest")]
    [InlineData("text/html;q=0,application/json;q=1", null, null, null)]
    public void Api_or_ambiguous_headers_do_not_select_html(string accept, string? mode, string? destination, string? xhr)
    {
        var context = new DefaultHttpContext();
        context.Request.Method = "POST";
        context.Request.Path = "/connect/device";
        context.Request.Headers.Accept = accept;
        context.Request.Headers.UserAgent = "Mozilla/5.0 Chrome/150";
        if (mode is not null) context.Request.Headers["Sec-Fetch-Mode"] = mode;
        if (destination is not null) context.Request.Headers["Sec-Fetch-Dest"] = destination;
        if (xhr is not null) context.Request.Headers["X-Requested-With"] = xhr;
        Assert.False(BrowserRateLimitErrors.IsHtmlNavigation(context.Request));
    }

    [Theory]
    [InlineData("/account/login/password")]
    [InlineData("/account/login/2fa")]
    [InlineData("/account/login/recoverycode")]
    [InlineData("/account/forgotpassword")]
    [InlineData("/account/resetpassword")]
    [InlineData("/account/register")]
    public async Task Interactive_account_forms_render_the_same_429_page(string path)
    {
        await using var app = await StartAsync();
        using var client = app.GetTestClient();
        using var first = await client.PostAsync(path, null);
        using var request = Navigation(path, "en-US");
        using var response = await client.SendAsync(request);
        Assert.Equal(HttpStatusCode.TooManyRequests, response.StatusCode);
        Assert.Equal("text/html", response.Content.Headers.ContentType?.MediaType);
        Assert.Contains("Please wait", await response.Content.ReadAsStringAsync());
    }

    [Fact]
    public async Task Token_rejection_keeps_json_and_uses_its_configured_retry_window()
    {
        var builder = WebApplication.CreateBuilder();
        builder.WebHost.UseTestServer();
        builder.Services.AddSufficitIdentityRateLimiter(new RateLimitOptions
        {
            PermitLimit = 1, WindowSeconds = 120, TokenWindowSeconds = 240
        }, "api");
        await using var app = builder.Build();
        app.UseRouting();
        app.UseRateLimiter();
        app.MapPost("/connect/token", () => Results.Ok());
        await app.StartAsync();
        using var client = app.GetTestClient();
        using var first = await client.PostAsync("/connect/token", null);
        using var response = await client.PostAsync("/connect/token", null);
        Assert.Equal(HttpStatusCode.TooManyRequests, response.StatusCode);
        Assert.Equal("application/json", response.Content.Headers.ContentType?.MediaType);
        Assert.InRange(response.Headers.RetryAfter!.Delta!.Value.TotalSeconds, 121, 240);
    }

    [Fact]
    public async Task Headless_host_preserves_json_for_interactive_routes()
    {
        await using var app = await StartAsync(embedded: false);
        using var client = app.GetTestClient();
        using var first = await client.PostAsync("/connect/device", null);
        using var request = Navigation("/connect/device", "en");
        using var response = await client.SendAsync(request);
        Assert.Equal(HttpStatusCode.TooManyRequests, response.StatusCode);
        Assert.Equal("application/json", response.Content.Headers.ContentType?.MediaType);
    }
}
