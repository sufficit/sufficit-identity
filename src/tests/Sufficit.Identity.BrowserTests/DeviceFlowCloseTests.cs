using Microsoft.Playwright;
using Microsoft.Playwright.NUnit;
using NUnit.Framework;

namespace Sufficit.Identity.BrowserTests;

[Parallelizable(ParallelScope.None)]
public sealed class DeviceFlowCloseTests : PageTest
{
    [Test]
    public async Task Script_opened_popup_closes_after_the_opener_reference_is_removed()
    {
        var popup = await Page.RunAndWaitForPopupAsync(async () =>
            await Page.EvaluateAsync("window.open('about:blank', '_blank')"));
        await popup.SetContentAsync("""
            <main data-device-flow-result>
                <button type="button" class="btn btn-primary btn-block" data-device-flow-close hidden>Fechar esta aba</button>
                <p data-device-close-fallback hidden>Fechamento manual</p>
            </main>
            """);
        await popup.AddStyleTagAsync(new PageAddStyleTagOptions
        {
            Path = ResolveIdentityStylesheet()
        });
        await popup.AddScriptTagAsync(new PageAddScriptTagOptions
        {
            Path = ResolveIdentityScript()
        });
        await popup.EvaluateAsync("window.opener = null");

        Assert.That(await popup.EvaluateAsync<bool>("window.opener === null"), Is.True);
        var closed = new TaskCompletionSource<bool>(
            TaskCreationOptions.RunContinuationsAsynchronously);
        popup.Close += (_, _) => closed.TrySetResult(true);

        try
        {
            await popup.Locator("[data-device-flow-close]").ClickAsync();
        }
        catch (PlaywrightException) when (popup.IsClosed)
        {
            // Chromium may destroy the target before ClickAsync receives its
            // completion acknowledgement. The close event below is decisive.
        }

        Assert.That(
            await closed.Task.WaitAsync(TimeSpan.FromSeconds(3)),
            Is.True);
    }

    [Test]
    public async Task Eligible_popup_keeps_close_control_after_all_strategies_are_blocked()
    {
        var popup = await Page.RunAndWaitForPopupAsync(async () =>
            await Page.EvaluateAsync("window.open('about:blank', '_blank')"));
        await popup.SetContentAsync("""
            <main data-device-flow-result>
                <button type="button" class="btn btn-primary btn-block" data-device-flow-close hidden>Fechar esta aba</button>
                <p data-device-close-fallback hidden>Fechamento manual</p>
            </main>
            """);
        await popup.AddStyleTagAsync(new PageAddStyleTagOptions
        {
            Path = ResolveIdentityStylesheet()
        });
        await popup.AddScriptTagAsync(new PageAddScriptTagOptions
        {
            Path = ResolveIdentityScript()
        });
        await popup.EvaluateAsync("""
            () => {
                window.__closeCalls = [];
                window.close = () => window.__closeCalls.push('window');
                window.open = () => ({
                    close: () => window.__closeCalls.push('retargeted')
                });
                window.opener = null;
            }
            """);

        await popup.Locator("[data-device-flow-close]").ClickAsync();
        await popup.Locator("[data-device-close-fallback]").WaitForAsync(
            new LocatorWaitForOptions { State = WaitForSelectorState.Visible });

        var closeCalls = await popup.EvaluateAsync<string[]>("window.__closeCalls");
        Assert.That(closeCalls, Is.EqualTo(new[] { "window", "window", "retargeted" }));
        Assert.That(
            await popup.Locator("[data-device-flow-close]").IsVisibleAsync(),
            Is.True);
        Assert.That(
            await popup.Locator("[data-device-flow-close]").IsEnabledAsync(),
            Is.True);

        await popup.CloseAsync();
    }

    [Test]
    public async Task Missing_opener_shows_manual_fallback_without_close_control()
    {
        await Page.SetContentAsync("""
            <main data-device-flow-result>
                <button type="button" class="btn btn-primary btn-block" data-device-flow-close hidden>Fechar esta aba</button>
                <p data-device-close-fallback hidden>Fechamento manual</p>
            </main>
            """);
        await Page.AddStyleTagAsync(new PageAddStyleTagOptions
        {
            Path = ResolveIdentityStylesheet()
        });
        await Page.EvaluateAsync("""
            () => {
                window.__closeCalls = [];
                window.__closeReports = [];
                window.close = () => window.__closeCalls.push('window');
                window.open = () => ({
                    close: () => window.__closeCalls.push('retargeted')
                });
                Object.defineProperty(navigator, 'sendBeacon', {
                    configurable: true,
                    value: (_url, body) => {
                        body.text().then(text => window.__closeReports.push(JSON.parse(text)));
                        return true;
                    }
                });
            }
            """);

        await Page.AddScriptTagAsync(new PageAddScriptTagOptions
        {
            Path = ResolveIdentityScript()
        });

        Assert.That(await Page.EvaluateAsync<bool>("window.opener === null"), Is.True);
        await Page.Locator("[data-device-close-fallback]").WaitForAsync(
            new LocatorWaitForOptions { State = WaitForSelectorState.Visible });

        var closeCalls = await Page.EvaluateAsync<string[]>("window.__closeCalls");
        Assert.That(closeCalls, Is.Empty);
        Assert.That(
            await Page.Locator("[data-device-flow-close]").IsHiddenAsync(),
            Is.True);
    }

    private static string ResolveIdentityScript()
    {
        var current = new DirectoryInfo(TestContext.CurrentContext.TestDirectory);
        while (current is not null)
        {
            var candidate = Path.Combine(
                current.FullName,
                "src",
                "ui",
                "Sufficit.Identity.UI",
                "wwwroot",
                "js",
                "identity.js");
            if (File.Exists(candidate))
            {
                return candidate;
            }

            current = current.Parent;
        }

        throw new FileNotFoundException("Unable to locate identity.js from the test directory.");
    }

    private static string ResolveIdentityStylesheet()
    {
        var current = new DirectoryInfo(TestContext.CurrentContext.TestDirectory);
        while (current is not null)
        {
            var candidate = Path.Combine(
                current.FullName,
                "src",
                "ui",
                "Sufficit.Identity.UI",
                "wwwroot",
                "css",
                "site.css");
            if (File.Exists(candidate))
            {
                return candidate;
            }

            current = current.Parent;
        }

        throw new FileNotFoundException("Unable to locate site.css from the test directory.");
    }
}
