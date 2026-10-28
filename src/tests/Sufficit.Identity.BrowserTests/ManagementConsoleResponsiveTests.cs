using Microsoft.Playwright;
using Microsoft.Playwright.NUnit;
using NUnit.Framework;

namespace Sufficit.Identity.BrowserTests;

/// <summary>
/// Plan E6: every Management page fits a phone. At 320, 360, 390 and 430 px
/// the document never scrolls sideways (wide tables scroll inside their own
/// container), and the closed navigation drawer is out of the tab order — it
/// sat off-screen but focusable until 2026-10-24.
/// </summary>
[Parallelizable(ParallelScope.None)]
public class ManagementConsoleResponsiveTests : PageTest
{
    private static readonly string[] Pages =
    [
        "/", "/clients", "/clients/new", "/users", "/claims", "/scopes", "/sessions",
        "/authorizations", "/audit", "/tokens", "/branding", "/settings",
        "/settings/trusted-proxies", "/system-users", "/metrics", "/database",
    ];

    [SetUp]
    public Task AuthenticateAsync() => ManagementSession.SignInAsync(Page);

    [TestCase(320)]
    [TestCase(360)]
    [TestCase(390)]
    [TestCase(430)]
    public async Task No_page_scrolls_sideways(int width)
    {
        await Page.SetViewportSizeAsync(width, 800);
        var overflowing = new List<string>();
        foreach (var path in Pages)
        {
            await Page.GotoAsync($"{ManagementSession.BaseUrl}/management{path}");
            await Page.WaitForLoadStateAsync(LoadState.NetworkIdle);
            var scrollWidth = await Page.EvaluateAsync<int>("() => document.documentElement.scrollWidth");
            if (scrollWidth > width)
                overflowing.Add($"{path} is {scrollWidth}px wide");
        }

        Assert.That(overflowing, Is.Empty, string.Join("\n", overflowing));
    }

    [Test]
    public async Task The_closed_drawer_is_out_of_the_tab_order_on_a_phone()
    {
        await Page.SetViewportSizeAsync(360, 800);
        await Page.GotoAsync($"{ManagementSession.BaseUrl}/management/");
        await Page.WaitForLoadStateAsync(LoadState.NetworkIdle);

        var visibility = await Page.EvaluateAsync<string>(
            "() => getComputedStyle(document.querySelector('.app-sidebar')).visibility");
        Assert.That(visibility, Is.EqualTo("hidden"));

        await Page.ClickAsync(".topbar-menu");
        await Page.WaitForTimeoutAsync(400);
        visibility = await Page.EvaluateAsync<string>(
            "() => getComputedStyle(document.querySelector('.app-sidebar')).visibility");
        Assert.That(visibility, Is.EqualTo("visible"));
    }
}
