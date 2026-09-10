using System.Net;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.TestHost;
using Microsoft.Extensions.DependencyInjection;
using Sufficit.Identity.Server;
using Xunit;

namespace Sufficit.Identity.Tests;

public sealed class DeviceBrowserLaunchTests
{
    private static async Task<WebApplication> StartAsync()
    {
        var builder = WebApplication.CreateBuilder();
        builder.WebHost.UseTestServer();
        builder.Services.AddRazorComponents();
        builder.Services.AddLocalization();
        var app = builder.Build();
        app.UseRequestLocalization(new RequestLocalizationOptions()
            .SetDefaultCulture("pt-BR").AddSupportedCultures("pt-BR", "en-US")
            .AddSupportedUICultures("pt-BR", "en-US"));
        app.MapDeviceBrowserLaunch();
        await app.StartAsync();
        return app;
    }

    [Theory]
    [InlineData("pt-BR", "Abrir autentica")]
    [InlineData("en-US", "Open sign-in")]
    public async Task Launcher_is_anonymous_localized_and_only_targets_same_origin_device_flow(string culture, string label)
    {
        await using var app = await StartAsync();
        using var client = app.GetTestClient();
        client.DefaultRequestHeaders.AcceptLanguage.ParseAdd(culture);
        using var response = await client.GetAsync("/device/launch?user_code=ABCD-EFGH&returnUrl=https://evil.invalid&device_code=SECRET");
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        Assert.True(response.Headers.CacheControl!.NoStore);
        Assert.Equal("no-referrer", Assert.Single(response.Headers.GetValues("Referrer-Policy")));
        Assert.Equal("same-origin-allow-popups", Assert.Single(response.Headers.GetValues("Cross-Origin-Opener-Policy")));
        var html = await response.Content.ReadAsStringAsync();
        Assert.Contains(label, WebUtility.HtmlDecode(html));
        Assert.Contains("/connect/device?user_code=ABCD-EFGH&amp;launch_mode=popup", html);
        Assert.DoesNotContain("evil.invalid", html);
        Assert.DoesNotContain("SECRET", html);
        Assert.Contains("device-launcher.js", html);
        if (Environment.GetEnvironmentVariable("SUFFICIT_AUTH_PREVIEW_DIR") is { Length: > 0 } directory)
        {
            Directory.CreateDirectory(directory);
            await File.WriteAllTextAsync(Path.Combine(directory, $"device-launcher-{culture}.html"), html);
        }
    }

    [Theory]
    [InlineData("")]
    [InlineData("<script>")]
    [InlineData("/../https://evil.invalid")]
    [InlineData("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA")]
    public async Task Invalid_codes_do_not_render_a_launcher(string code)
    {
        await using var app = await StartAsync();
        using var client = app.GetTestClient();
        using var response = await client.GetAsync("/device/launch?user_code=" + Uri.EscapeDataString(code));
        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
    }
}
