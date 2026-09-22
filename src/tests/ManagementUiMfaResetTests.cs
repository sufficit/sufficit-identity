using System.Diagnostics;
using System.Net;
using Microsoft.AspNetCore.TestHost;
using Xunit;

namespace Sufficit.Identity.Tests;

public sealed partial class ManagementUiRoutingTests
{
    [Theory]
    [InlineData("/management/users/user-1")]
    [InlineData("/management/users/user-1/edit")]
    public async Task User_screens_offer_administrative_mfa_recovery(string path)
    {
        await using var app = await CreateHostAsync();
        using var client = app.GetTestClient();
        await SignInAsync(client, "administrator");
        using var response = await client.GetAsync(path);
        response.EnsureSuccessStatusCode();
        var html = WebUtility.HtmlDecode(await response.Content.ReadAsStringAsync());
        Assert.Contains("Redefinir autenticação de dois fatores", html);
        Assert.Contains("Verifique a identidade do titular", html);
    }

    [Fact]
    public async Task Mfa_reset_browser_exercises_confirmation_and_mobile_layout()
    {
        var script = Environment.GetEnvironmentVariable("IDENTITY_MFA_BROWSER_SCRIPT");
        if (string.IsNullOrWhiteSpace(script)) return;
        await using var app = await CreateHostAsync(useKestrel: true);
        var start = new ProcessStartInfo("node") { RedirectStandardOutput = true, RedirectStandardError = true };
        start.ArgumentList.Add(script);
        start.ArgumentList.Add(app.Urls.Single());
        using var process = Process.Start(start)!;
        var stdout = process.StandardOutput.ReadToEndAsync();
        var stderr = process.StandardError.ReadToEndAsync();
        using var timeout = new CancellationTokenSource(TimeSpan.FromMinutes(2));
        try { await process.WaitForExitAsync(timeout.Token); }
        finally { if (!process.HasExited) process.Kill(entireProcessTree: true); }
        Assert.True(process.ExitCode == 0, await stdout + "\n" + await stderr);
    }
}
