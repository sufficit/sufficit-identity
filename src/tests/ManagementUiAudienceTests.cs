using System.Diagnostics;
using System.Net;
using System.Text.RegularExpressions;
using Microsoft.AspNetCore.TestHost;
using Xunit;

namespace Sufficit.Identity.Tests;

public sealed partial class ManagementUiRoutingTests
{
    [Fact]
    public async Task Audiences_require_operator_access_and_render_inventory()
    {
        await using var app = await CreateHostAsync();
        using var client = app.GetTestClient();
        using var anonymous = await client.GetAsync("/management/audiences");
        Assert.Equal(HttpStatusCode.Redirect, anonymous.StatusCode);
        await SignInAsync(client, "manager");
        using var denied = await client.GetAsync("/management/audiences");
        Assert.Equal(HttpStatusCode.Redirect, denied.StatusCode);
        client.DefaultRequestHeaders.Remove("Cookie");
        await SignInAsync(client, "administrator");
        using var response = await client.GetAsync("/management/audiences");
        response.EnsureSuccessStatusCode();
        var html = WebUtility.HtmlDecode(await response.Content.ReadAsStringAsync());
        Assert.Contains("Audiências registradas", html);
        Assert.Contains("test-api", html);
        Assert.Contains("test.scope", html);
        Assert.Contains("test-client", html);
        Assert.Contains("Vincular audiência", html);
        Assert.Matches("<a[^>]*href=\"audiences\"[^>]*class=\"nav-item active\"", html);
    }

    [Theory]
    [InlineData("settings/trusted-proxies", "settings/trusted-proxies")]
    [InlineData("settings", "settings")]
    public async Task Settings_and_proxies_have_only_one_active_link(string route, string active)
    {
        await using var app = await CreateHostAsync();
        using var client = app.GetTestClient();
        await SignInAsync(client, "administrator");
        using var response = await client.GetAsync($"/management/{route}");
        response.EnsureSuccessStatusCode();
        var html = await response.Content.ReadAsStringAsync();
        var links = Regex.Matches(html, "<a[^>]*class=\"nav-item active\"[^>]*>");
        Assert.Single(links);
        Assert.Contains($"href=\"{active}\"", links[0].Value);
    }

    // Always exercises the real HTTP host. Set IDENTITY_AUDIENCE_BROWSER_SCRIPT
    // to run the optional Playwright interaction/viewport checks against it too.
    [Fact]
    public async Task Audience_browser_host_serves_authenticated_screen()
    {
        await using var app = await CreateHostAsync(useKestrel: true);
        var address = app.Urls.Single();
        using var client = new HttpClient { BaseAddress = new Uri(address) };
        await SignInAsync(client, "administrator");
        using var response = await client.GetAsync("/management/audiences");
        response.EnsureSuccessStatusCode();
        Assert.Contains("test-api", await response.Content.ReadAsStringAsync());
        var script = Environment.GetEnvironmentVariable("IDENTITY_AUDIENCE_BROWSER_SCRIPT");
        if (string.IsNullOrWhiteSpace(script)) return;
        var start = new ProcessStartInfo("node") { RedirectStandardOutput = true, RedirectStandardError = true };
        start.ArgumentList.Add(script);
        start.ArgumentList.Add(address);
        using var process = Process.Start(start)!;
        var stdout = process.StandardOutput.ReadToEndAsync();
        var stderr = process.StandardError.ReadToEndAsync();
        using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(90));
        try { await process.WaitForExitAsync(timeout.Token); }
        catch (OperationCanceledException) { process.Kill(entireProcessTree: true); throw; }
        Assert.True(process.ExitCode == 0, $"Browser checks failed: {await stdout}\n{await stderr}");
    }
}
