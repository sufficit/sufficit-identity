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
    [InlineData("ABCD-EFGH")]
    [InlineData("2705-5719-6354")]
    [InlineData("ABCD EFGH")]
    public async Task Launcher_redirects_to_same_origin_device_flow_without_an_intermediate_page(string code)
    {
        await using var app = await StartAsync();
        using var client = app.GetTestClient();
        using var response = await client.GetAsync("/device/launch?user_code=" + Uri.EscapeDataString(code)
            + "&launch_mode=popup&returnUrl=https://evil.invalid&device_code=SECRET");
        Assert.Equal(HttpStatusCode.Redirect, response.StatusCode);
        Assert.True(response.Headers.CacheControl!.NoStore);
        Assert.Equal("no-referrer", Assert.Single(response.Headers.GetValues("Referrer-Policy")));
        Assert.Equal("same-origin-allow-popups", Assert.Single(response.Headers.GetValues("Cross-Origin-Opener-Policy")));
        Assert.Equal("/connect/device?user_code=" + Uri.EscapeDataString(code) + "&launch_mode=popup",
            response.Headers.Location!.OriginalString);
        Assert.Empty(await response.Content.ReadAsStringAsync());
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
