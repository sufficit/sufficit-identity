using Microsoft.Playwright;
using Microsoft.Playwright.NUnit;
using NUnit.Framework;

namespace Sufficit.Identity.BrowserTests;

/// <summary>
/// Verifies that a real Chromium parses the SUI stylesheet on a deployed
/// environment's public login page (no authentication required). Run with
/// SUFFICIT_TEST_BASE_URL pointing at the deployment to check, e.g.
/// https://identity.sufficit.com.br.
/// </summary>
[Parallelizable(ParallelScope.None)]
public class ProdLoginCssCheck : PageTest
{
    private static readonly string BaseUrl =
        Environment.GetEnvironmentVariable("SUFFICIT_TEST_BASE_URL")
        ?? "https://localhost:5001";

    [Test]
    public async Task Login_page_applies_sui_styles()
    {
        TestServerProbe.EnsureServerAvailable();
        await Page.GotoAsync($"{BaseUrl}/account/login");
        await Page.WaitForLoadStateAsync(LoadState.NetworkIdle);
        await Page.WaitForTimeoutAsync(1500);

        var rules = await DomHealthChecks.GetStylesheetRuleCountAsync(Page, "sufficit-ui.css");
        Assert.That(rules, Is.GreaterThan(300),
            $"sufficit-ui.css parsed to {rules} rules; expected the full ~400-rule bundle. " +
            "An empty/truncated stylesheet means the gzip variant or content negotiation is broken.");

        var primary = await Page.EvaluateAsync<string>(
            "() => getComputedStyle(document.documentElement).getPropertyValue('--sui-color-primary').trim()");
        Assert.That(primary, Is.Not.Empty,
            "--sui-color-primary did not resolve; SUI foundations are not applying.");
        TestContext.Out.WriteLine($"sufficit-ui.css rules: {rules}; --sui-color-primary: {primary}");
    }
}
