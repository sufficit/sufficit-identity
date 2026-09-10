using Microsoft.Playwright;
using Microsoft.Playwright.NUnit;
using NUnit.Framework;

namespace Sufficit.Identity.BrowserTests;

[Parallelizable(ParallelScope.None)]
public sealed class DeviceBrowserLauncherTests : PageTest
{
    private const string Origin = "http://identity.launcher.test";
    private const string Markup = """
        <main data-device-launcher>
          <a data-device-launch href="/connect/device?launch_mode=popup">Open</a>
          <p data-device-waiting hidden>Waiting</p><p data-device-complete hidden>Done</p>
          <p data-device-denied hidden>Denied</p><p data-device-blocked hidden>Blocked</p>
          <a data-device-manual hidden href="/connect/device">Manual</a>
        </main><script src="/device-launcher.js"></script>
        """;

    private static string Script(string name)
    {
        var directory = new DirectoryInfo(TestContext.CurrentContext.TestDirectory);
        while (directory is not null && !File.Exists(Path.Combine(directory.FullName, "Sufficit.Identity.sln")))
            directory = directory.Parent;
        return File.ReadAllText(Path.Combine(directory!.FullName, "src/ui/Sufficit.Identity.UI/wwwroot/js", name));
    }

    private async Task PrepareAsync(bool replaceInitialDocument)
    {
        await Context.RouteAsync(Origin + "/**", async route =>
        {
            var path = new Uri(route.Request.Url).AbsolutePath;
            var body = path switch
            {
                "/device-launcher.js" => Script("device-launcher.js"),
                "/identity.js" => Script("identity.js"),
                "/connect/device" => "<button id='done'>Complete</button>",
                _ => Markup
            };
            await route.FulfillAsync(new RouteFulfillOptions
            {
                ContentType = path.EndsWith(".js") ? "text/javascript" : "text/html",
                Headers = new Dictionary<string, string> { ["Cross-Origin-Opener-Policy"] = "same-origin-allow-popups" },
                Body = body
            });
        });
        if (replaceInitialDocument)
        {
            await Page.EvaluateAsync("url => location.replace(url)", Origin + "/launch");
            await Page.WaitForURLAsync(Origin + "/launch");
        }
        else await Page.GotoAsync(Origin + "/launch");
        await Page.Locator("[data-device-launch]").WaitForAsync();
    }

    [TestCase("approved")]
    [TestCase("denied")]
    public async Task Same_origin_popup_and_fresh_external_launcher_close_after_completion(string result)
    {
        await PrepareAsync(replaceInitialDocument: true);
        Assert.That(await Page.EvaluateAsync<int>("history.length"), Is.EqualTo(1));
        Assert.That(await Page.EvaluateAsync<bool>("opener === null"), Is.True);
        var popup = await Page.RunAndWaitForPopupAsync(() => Page.Locator("[data-device-launch]").ClickAsync());
        await popup.WaitForLoadStateAsync();
        Assert.That(await popup.EvaluateAsync<bool>("!!opener"), Is.True);
        await Page.EvaluateAsync("window.postMessage({type:'sufficit-auth-complete',flow:'device',result:'approved'},location.origin)");
        await Expect(Page.Locator("[data-device-complete]")).ToBeHiddenAsync();
        var closed = new TaskCompletionSource<bool>(TaskCreationOptions.RunContinuationsAsynchronously);
        Page.Close += (_, _) => closed.TrySetResult(true);
        await popup.SetContentAsync($"""
            <main data-device-flow-result="{result}" data-device-launch-mode="popup">
              <button data-device-flow-close>Close</button><p data-device-close-fallback hidden>Manual</p>
            </main>
            """);
        try { await popup.AddScriptTagAsync(new PageAddScriptTagOptions { Url = Origin + "/identity.js" }); }
        catch (PlaywrightException) when (popup.IsClosed) { }
        Assert.That(await closed.Task.WaitAsync(TimeSpan.FromSeconds(5)), Is.True);
        Assert.That(popup.IsClosed, Is.True);
    }

    [Test]
    public async Task Popup_blocked_keeps_a_direct_manual_link()
    {
        await PrepareAsync(replaceInitialDocument: false);
        await Page.EvaluateAsync("window.open = () => null");
        await Page.Locator("[data-device-launch]").ClickAsync();
        await Expect(Page.Locator("[data-device-blocked]")).ToBeVisibleAsync();
        await Expect(Page.Locator("[data-device-manual]")).ToBeVisibleAsync();
        await Expect(Page.Locator("[data-device-complete]")).ToBeHiddenAsync();
    }

    [Test]
    public async Task Reused_launcher_keeps_completion_visible_when_browser_refuses_close()
    {
        await PrepareAsync(replaceInitialDocument: false);
        var popup = await Page.RunAndWaitForPopupAsync(() => Page.Locator("[data-device-launch]").ClickAsync());
        await popup.WaitForLoadStateAsync();
        // Simulate the browser refusing to close the launcher, without weakening popup checks.
        await Page.EvaluateAsync("window.close = () => { window.closeAttempted = true; }");
        await popup.EvaluateAsync("opener.postMessage({type:'sufficit-auth-complete',flow:'device',result:'approved'},location.origin)");
        await Page.WaitForFunctionAsync("window.closeAttempted === true");
        await Expect(Page.Locator("[data-device-complete]")).ToBeVisibleAsync();
        Assert.That(popup.IsClosed, Is.True);
    }
}
