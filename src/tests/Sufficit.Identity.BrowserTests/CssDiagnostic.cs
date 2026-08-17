using System.Text.Json;
using Microsoft.Playwright;
using Microsoft.Playwright.NUnit;
using NUnit.Framework;

namespace Sufficit.Identity.BrowserTests;

/// <summary>
/// On-demand diagnostic: dumps every stylesheet, link element and the
/// management users-page body state (filter form visibility, screenshots)
/// to troubleshoot CSS application and circuit-render issues. Not part of
/// the automated health suite — run explicitly when investigating UI reports.
/// Authenticates and then elevates the session with dev-only MFA claims so
/// the management console renders past its amr=mfa gate.
/// </summary>
[Parallelizable(ParallelScope.None)]
public class CssDiagnostic : PageTest
{
    private static readonly string BaseUrl =
        Environment.GetEnvironmentVariable("SUFFICIT_TEST_BASE_URL")
        ?? "https://localhost:5001";

    [Test]
    public async Task Dump_stylesheet_state_login_vs_management()
    {
        // --- LOGIN PAGE ---
        await Page.GotoAsync($"{BaseUrl}/account/login");
        await Page.WaitForLoadStateAsync(LoadState.NetworkIdle);
        TestContext.Out.WriteLine("===== LOGIN PAGE =====");
        await DumpSheetsAsync("login");

        // --- AUTHENTICATE ---
        await Page.Locator("#username, input[name='UserName']").First.FillAsync("browsertest");
        await Page.Locator("#password, input[name='Password']").First.FillAsync("BrowserTest2026!");
        await Page.ClickAsync("button[type='submit']");
        await Page.WaitForURLAsync(url => !url.Contains("/account/login"),
            new PageWaitForURLOptions { Timeout = 15_000 });

        // Elevate the session with MFA claims (management pages require
        // amr=mfa); dev-only endpoint, mirrors ManagementConsoleHealthTests.
        await Page.EvaluateAsync(@"async () => {
            await fetch('/__test__/signin', {
                method: 'POST',
                headers: { 'content-type': 'application/x-www-form-urlencoded' },
                body: 'username=browsertest&mfa=true',
                credentials: 'same-origin'
            });
        }");

        // --- MANAGEMENT USERS PAGE ---
        await Page.GotoAsync($"{BaseUrl}/management/users");
        await Page.WaitForLoadStateAsync(LoadState.NetworkIdle);
        await Page.WaitForTimeoutAsync(2000); // let the circuit settle
        TestContext.Out.WriteLine("===== MANAGEMENT USERS PAGE =====");
        await DumpSheetsAsync("management");

        var bodyState = await Page.EvaluateAsync<string>(@"() => JSON.stringify({
            url: location.href,
            title: document.title,
            hasFilterPanel: !!document.querySelector('.users-filter-panel'),
            hasFilterForm: !!document.querySelector('.users-filter-form'),
            hasSelectTrigger: !!document.querySelector('.sui-select__trigger'),
            hasTable: !!document.querySelector('table'),
            hasReconnectModal: !!document.querySelector('#components-reconnect-modal, .reconnect-modal'),
            bodyTextStart: (document.body.innerText || '').slice(0, 300)
        }, null, 1)");
        TestContext.Out.WriteLine($"BODY {bodyState}");
        await Page.WaitForTimeoutAsync(3000);
        var bodyState2 = await Page.EvaluateAsync<string>(@"() => JSON.stringify({
            url: location.href,
            hasFilterForm: !!document.querySelector('.users-filter-form'),
            filterPanelOpen: (() => { const d = document.querySelector('.users-filter-panel'); return d ? d.open : null; })(),
            filterFormVisible: (() => { const f = document.querySelector('.users-filter-form'); return f ? f.getBoundingClientRect().height > 0 : false; })(),
            hasTable: !!document.querySelector('table'),
            mainText: (() => { const m = document.querySelector('main, [class*=""content""]'); return (m ? m.innerText : document.body.innerText || '').slice(0, 900); })()
        }, null, 1)");
        TestContext.Out.WriteLine($"BODY-AFTER-3s {bodyState2}");
        await Page.ScreenshotAsync(new PageScreenshotOptions
        {
            Path = "/tmp/management-users.png",
            FullPage = true
        });
        TestContext.Out.WriteLine("screenshot: /tmp/management-users.png");
    }

    private async Task DumpSheetsAsync(string label)
    {
        // Every stylesheet in document.styleSheets with href, rules, and access error
        var sheetDump = await Page.EvaluateAsync<string>(@"() => JSON.stringify(
            Array.from(document.styleSheets).map(s => ({
                href: s.href,
                rules: (() => { try { return s.cssRules.length; } catch (e) { return 'ERR:' + e.name; } })(),
                media: s.media.mediaText,
                disabled: s.disabled
            })), null, 1)");
        using var doc = JsonDocument.Parse(sheetDump);
        foreach (var sheet in doc.RootElement.EnumerateArray())
        {
            var href = sheet.GetProperty("href").GetString() ?? "(inline)";
            TestContext.Out.WriteLine(
                $"SHEET rules={sheet.GetProperty("rules")} media='{sheet.GetProperty("media").GetString()}' disabled={sheet.GetProperty("disabled").GetBoolean()} href={href}");
        }

        // Every link[rel=stylesheet] in the DOM right now
        var linkDump = await Page.EvaluateAsync<string>(@"() => JSON.stringify(
            Array.from(document.querySelectorAll('link[rel=""stylesheet""]')).map(l => ({
                href: l.getAttribute('href'),
                resolved: l.href,
                inHead: l.closest('head') !== null,
                loaded: l.sheet !== null
            })))");
        using var links = JsonDocument.Parse(linkDump);
        foreach (var link in links.RootElement.EnumerateArray())
        {
            TestContext.Out.WriteLine(
                $"LINK attr={link.GetProperty("href").GetString()} resolved={link.GetProperty("resolved").GetString()} inHead={link.GetProperty("inHead").GetBoolean()} hasSheet={link.GetProperty("loaded").GetBoolean()}");
        }

        // Re-fetch the SUI css from page context: what content arrives?
        var fetchDump = await Page.EvaluateAsync<string>(@"async () => {
            const suiLink = Array.from(document.querySelectorAll('link[rel=""stylesheet""]'))
                .find(l => (l.getAttribute('href') || '').includes('sufficit-ui'));
            if (!suiLink) return JSON.stringify({ error: 'no sufficit-ui link in DOM' });
            const url = new URL(suILinkHrefFix(suiLink), location.href).href;
            function suILinkHrefFix(l) { return l.getAttribute('href'); }
            const r = await fetch(url);
            const text = await r.text();
            return JSON.stringify({
                url,
                status: r.status,
                contentType: r.headers.get('content-type'),
                byteLength: new TextEncoder().encode(text).length,
                head: text.slice(0, 200)
            }, null, 1);
        }");
        TestContext.Out.WriteLine($"FETCH {fetchDump}");

        // Computed style of a SUI-variable-driven element to see if vars resolve
        var computed = await Page.EvaluateAsync<string>(@"() => {
            const el = document.querySelector('.sui-select__trigger, .users-filter-form, form');
            if (!el) return '(no probe element)';
            const cs = getComputedStyle(el);
            return JSON.stringify({
                display: cs.display,
                position: cs.position,
                font: cs.fontFamily,
                primaryVar: getComputedStyle(document.documentElement)
                    .getPropertyValue('--sui-color-primary') || '(unset)'
            });
        }");
        TestContext.Out.WriteLine($"COMPUTED {computed}");
    }
}
