using System.Net;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.Extensions.DependencyInjection;
using OpenIddict.Server;
using Microsoft.Extensions.Options;
using Sufficit.Identity.Server;
using Sufficit.Identity.Tests.Infrastructure;
using Xunit;

namespace Sufficit.Identity.Tests;

[Collection(StsCollection.Name)]
public sealed class BrowserAuthorizationErrorTests(SufficitIdentityTestFactory factory)
{
    [Theory]
    [InlineData("/connect/authorize", "text/html", null, null, true)]
    [InlineData("/connect/authorize", "text/html", "navigate", "document", true)]
    [InlineData("/connect/endsession", "text/html", "navigate", "document", true)]
    [InlineData("/connect/device", "text/html", "navigate", "document", true)]
    [InlineData("/connect/device", "application/json", "navigate", "document", false)]
    [InlineData("/connect/device", "text/html", "cors", "empty", false)]
    [InlineData("/connect/device", "text/html", "navigate", "iframe", false)]
    [InlineData("/connect/device/info", "text/html", "navigate", "document", false)]
    [InlineData("/connect/deviceauthorization", "text/html", "navigate", "document", false)]
    [InlineData("/connect/authorize", "text/html;q=0", "navigate", "document", false)]
    [InlineData("/connect/authorize", "application/json,text/html;q=0.5", null, null, false)]
    [InlineData("/connect/authorize", "*/*", null, null, false)]
    [InlineData("/connect/authorize", null, null, null, false)]
    [InlineData("/connect/authorize", "text/html", "cors", "empty", false)]
    [InlineData("/connect/authorize", "text/html", "navigate", "iframe", false)]
    [InlineData("/connect/token", "text/html", "navigate", "document", false)]
    [InlineData("/connect/introspect", "text/html", "navigate", "document", false)]
    [InlineData("/api/account/tokens", "text/html", "navigate", "document", false)]
    public void Presentation_requires_explicit_top_level_html_on_an_interactive_route(
        string path, string? accept, string? mode, string? destination, bool expected)
    {
        var request = new DefaultHttpContext().Request;
        request.Method = "GET";
        request.Path = path;
        if (accept is not null) request.Headers.Accept = accept;
        if (mode is not null) request.Headers["Sec-Fetch-Mode"] = mode;
        if (destination is not null) request.Headers["Sec-Fetch-Dest"] = destination;
        Assert.Equal(expected, BrowserAuthorizationErrors.IsHtmlNavigation(request));
        request.Method = "POST";
        Assert.Equal(expected && path == "/connect/device", BrowserAuthorizationErrors.IsHtmlNavigation(request));
    }

    [Theory]
    [InlineData("text/html", true)]
    [InlineData("application/json", false)]
    [InlineData("*/*", false)]
    [InlineData("application/json,text/html;q=0.5", false)]
    public async Task Unavailable_device_verification_uses_html_only_for_browser_navigation(
        string accept, bool expectsHtml)
    {
        using var isolated = SufficitIdentityTestFactory.CreateIsolated(new Dictionary<string, string?>());
        await ((IAsyncLifetime)isolated).InitializeAsync();
        using var client = isolated.CreateClient(new WebApplicationFactoryClientOptions { AllowAutoRedirect = false });
        var options = isolated.Services.GetRequiredService<IOptionsMonitor<OpenIddictServerOptions>>().CurrentValue;
        options.UserCodeLifetime = options.DeviceCodeLifetime = TimeSpan.FromDays(-1);
        var (status, body) = await client.PostFormAsync("/connect/deviceauthorization", new Dictionary<string, string>
        {
            ["client_id"] = TestDataSeeder.DeviceClientId,
            ["client_secret"] = TestDataSeeder.DeviceClientSecret,
            ["scope"] = "openid",
        });
        Assert.Equal(HttpStatusCode.OK, status);
        var userCode = body.GetProperty("user_code").GetString()!;
        await TestOnlyEndpoints.SignInAsync(client, TestDataSeeder.DefaultUsername);
        var antiforgery = await TestOnlyEndpoints.GetAntiforgeryTokenAsync(client);
        using var request = new HttpRequestMessage(HttpMethod.Post, "/connect/device")
        {
            Content = new FormUrlEncodedContent(new Dictionary<string, string>
            {
                ["user_code"] = userCode,
                ["approved"] = "true",
                ["__RequestVerificationToken"] = antiforgery,
            })
        };
        request.Headers.Accept.ParseAdd(accept);
        request.Headers.Add("Sec-Fetch-Mode", "navigate");
        request.Headers.Add("Sec-Fetch-Dest", "document");
        using var response = await client.SendAsync(request);
        var content = await response.Content.ReadAsStringAsync();
        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
        Assert.Null(response.Headers.Location);
        if (expectsHtml)
        {
            Assert.Equal("text/html", response.Content.Headers.ContentType?.MediaType);
            Assert.Contains("Não foi possível continuar este acesso", WebUtility.HtmlDecode(content));
            Assert.Contains("Volte ao aplicativo e inicie o acesso novamente", WebUtility.HtmlDecode(content));
            Assert.Contains("authorization-error.css", content);
            Assert.Contains("href=\"/\"", content);
            Assert.DoesNotContain(userCode, content);
            Assert.DoesNotContain("error_description", content);
            Assert.True(response.Headers.CacheControl?.NoStore);
            Assert.Contains("no-referrer", response.Headers.GetValues("Referrer-Policy"));
        }
        else
        {
            Assert.Equal("application/json", response.Content.Headers.ContentType?.MediaType);
            Assert.Contains("invalid_grant", content);
        }
    }

    [Fact]
    public async Task Invalid_request_reference_returns_friendly_html_without_reflecting_untrusted_data()
    {
        using var client = factory.CreateClient(new WebApplicationFactoryClientOptions { AllowAutoRedirect = false });
        using var request = new HttpRequestMessage(HttpMethod.Get,
            "/connect/authorize?client_id=" + TestDataSeeder.AuthorizationCodeClientId
            + "&request_uri=urn:ietf:params:oauth:request_uri:private-reference&redirect_uri=https://untrusted.invalid/");
        request.Headers.Accept.ParseAdd("text/html");
        request.Headers.Add("Sec-Fetch-Mode", "navigate");
        request.Headers.Add("Sec-Fetch-Dest", "document");
        using var response = await client.SendAsync(request);
        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
        Assert.Equal("text/html", response.Content.Headers.ContentType?.MediaType);
        var html = await response.Content.ReadAsStringAsync();
        Assert.Contains("Não foi possível continuar este acesso", WebUtility.HtmlDecode(html));
        Assert.DoesNotContain("private-reference", html);
        Assert.DoesNotContain("untrusted.invalid", html);
        Assert.DoesNotContain("error_description", html);
        Assert.Null(response.Headers.Location);
        Assert.True(response.Headers.CacheControl?.NoStore);
        Assert.Contains("no-referrer", response.Headers.GetValues("Referrer-Policy"));
        if (Environment.GetEnvironmentVariable("SUFFICIT_AUTH_PREVIEW_DIR") is { Length: > 0 } directory)
        {
            Directory.CreateDirectory(directory);
            await File.WriteAllTextAsync(Path.Combine(directory, "identity-error.html"), html);
        }
    }

    [Theory]
    [InlineData("application/json")]
    [InlineData("*/*")]
    public async Task Machine_authorization_error_keeps_its_protocol_response(string accept)
    {
        using var client = factory.CreateClient(new WebApplicationFactoryClientOptions { AllowAutoRedirect = false });
        using var request = new HttpRequestMessage(HttpMethod.Get, "/connect/authorize?client_id=unknown-client");
        request.Headers.Accept.ParseAdd(accept);
        using var response = await client.SendAsync(request);
        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
        Assert.NotEqual("text/html", response.Content.Headers.ContentType?.MediaType);
        Assert.Contains("error", await response.Content.ReadAsStringAsync());
    }

    [Fact]
    public async Task Token_api_does_not_render_html_even_when_given_browser_headers()
    {
        using var client = factory.CreateClient();
        using var request = new HttpRequestMessage(HttpMethod.Post, "/connect/token");
        request.Headers.Accept.ParseAdd("text/html");
        request.Headers.Add("Sec-Fetch-Mode", "navigate");
        request.Headers.Add("Sec-Fetch-Dest", "document");
        request.Content = new FormUrlEncodedContent(new Dictionary<string,string> { ["grant_type"] = "invalid" });
        using var response = await client.SendAsync(request);
        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
        Assert.Equal("application/json", response.Content.Headers.ContentType?.MediaType);
        Assert.Contains("\"error\"", await response.Content.ReadAsStringAsync());
    }
}
