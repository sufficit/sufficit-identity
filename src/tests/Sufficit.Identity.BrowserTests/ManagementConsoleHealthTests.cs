using Microsoft.Playwright;
using Microsoft.Playwright.NUnit;
using NUnit.Framework;

namespace Sufficit.Identity.BrowserTests;

/// <summary>
/// Chrome DevTools-level health checks for the Identity Management UI.
/// Detects the exact classes of issues the browser surfaces that
/// server-side tests cannot: console warnings (form autofill, preload),
/// 404 resources, CSS files that load but don't apply, and overlapping
/// layout in the filter panels.
///
/// Requires a running Identity server (SUFFICIT_TEST_BASE_URL, default
/// https://localhost:5001) and test credentials (SUFFICIT_TEST_USER /
/// SUFFICIT_TEST_PASSWORD). Playwright browsers: `dotnet pwsh bin/Debug/net10.0/playwright.ps1 install chromium`.
/// </summary>
[Parallelizable(ParallelScope.None)]
public class ManagementConsoleHealthTests : PageTest
{
    private static readonly string BaseUrl =
        Environment.GetEnvironmentVariable("SUFFICIT_TEST_BASE_URL")
        ?? "https://localhost:5001";

    private static readonly string TestUser =
        Environment.GetEnvironmentVariable("SUFFICIT_TEST_USER")
        ?? "admin@sufficit.com.br";

    private static readonly string TestPassword =
        Environment.GetEnvironmentVariable("SUFFICIT_TEST_PASSWORD")
        ?? "";

    private ConsoleCollector _console = null!;

    [SetUp]
    public async Task NavigateAndAuthenticateAsync()
    {
        if (string.IsNullOrEmpty(TestPassword)) Assert.Ignore(
            "SUFFICIT_TEST_PASSWORD not set — management UI tests need credentials");

        _console = new ConsoleCollector(Page);

        // Navigate and authenticate
        await Page.GotoAsync($"{BaseUrl}/account/login");
        await Page.FillAsync("input[name='userName'], input[type='email']", TestUser);
        await Page.FillAsync("input[name='password'], input[type='password']", TestPassword);
        await Page.ClickAsync("button[type='submit']");

        // Wait for redirect to complete
        await Page.WaitForURLAsync(url => !url.Contains("/account/login"),
            new PageWaitForURLOptions { Timeout = 15_000 });
    }

    [TearDown]
    public async Task CleanupConsoleAsync()
    {
        if (_console is not null)
        {
            await _console.DisposeAsync();
        }
    }

    [Test]
    [Description("No JavaScript errors on the management dashboard")]
    public async Task Dashboard_has_no_console_errors()
    {
        await Page.GotoAsync($"{BaseUrl}/management/");
        await Page.WaitForLoadStateAsync(LoadState.NetworkIdle);

        Assert.That(_console.Errors, Is.Empty,
            $"Console errors on /management/:\n{FormatEntries(_console.Errors)}");
    }

    [Test]
    [Description("No form fields without id/name — Chrome autofill warning")]
    public async Task Users_page_has_no_autofill_warnings()
    {
        await Page.GotoAsync($"{BaseUrl}/management/users");
        await Page.WaitForLoadStateAsync(LoadState.NetworkIdle);

        // Chrome's autofill warning appears in the console
        Assert.That(_console.AutofillWarnings, Is.Empty,
            $"Chrome autofill warnings:\n{FormatEntries(_console.AutofillWarnings)}");

        // DOM-level check: no form fields missing both id and name
        var fieldsWithoutIdentity =
            await DomHealthChecks.GetFormFieldsWithoutIdentityAsync(Page);
        Assert.That(fieldsWithoutIdentity, Is.Empty,
            $"Form fields without id/name:\n{string.Join("\n", fieldsWithoutIdentity)}");
    }

    [Test]
    [Description("No 404 or failed resources on the users page")]
    public async Task Users_page_has_no_failed_resources()
    {
        await Page.GotoAsync($"{BaseUrl}/management/users");
        await Page.WaitForLoadStateAsync(LoadState.NetworkIdle);

        Assert.That(_console.ResourceFailures, Is.Empty,
            $"Failed requests:\n{string.Join("\n", _console.ResourceFailures)}");
    }

    [Test]
    [Description("SUI stylesheet loads and has CSS rules applied")]
    public async Task Sui_stylesheets_are_applied()
    {
        await Page.GotoAsync($"{BaseUrl}/management/users");
        await Page.WaitForLoadStateAsync(LoadState.NetworkIdle);

        var suiRules = await DomHealthChecks.GetStylesheetRuleCountAsync(
            Page, "sufficit-ui.css");
        Assert.That(suiRules, Is.GreaterThan(0),
            $"sufficit-ui.css loaded but has {suiRules} rules — CSS not parsing or empty");

        var appRules = await DomHealthChecks.GetStylesheetRuleCountAsync(
            Page, "app.css");
        Assert.That(appRules, Is.GreaterThan(0),
            $"app.css loaded but has {appRules} rules — CSS not parsing or empty");

        var usersRules = await DomHealthChecks.GetStylesheetRuleCountAsync(
            Page, "users.css");
        Assert.That(usersRules, Is.GreaterThan(0),
            $"users.css loaded but has {usersRules} rules — CSS not parsing or empty");
    }

    [Test]
    [Description("Filter form controls have computed styles (border, min-height)")]
    public async Task Users_filter_controls_are_styled()
    {
        await Page.GotoAsync($"{BaseUrl}/management/users");
        await Page.WaitForLoadStateAsync(LoadState.NetworkIdle);

        // Wait for the filter panel to render
        await Page.WaitForSelectorAsync(".users-filter-form",
            new PageWaitForSelectorOptions { Timeout = 10_000 });

        var unstyledControls = await DomHealthChecks.GetUnstyledFormControlsAsync(
            Page, ".users-filter-form");
        Assert.That(unstyledControls, Is.Empty,
            $"Unstyled form controls in filter panel:\n{string.Join("\n", unstyledControls)}");
    }

    [Test]
    [Description("Filter form fields do not overlap (CSS Grid is working)")]
    public async Task Users_filter_fields_do_not_overlap()
    {
        await Page.GotoAsync($"{BaseUrl}/management/users");
        await Page.WaitForLoadStateAsync(LoadState.NetworkIdle);

        await Page.WaitForSelectorAsync(".users-filter-form",
            new PageWaitForSelectorOptions { Timeout = 10_000 });

        var overlaps = await DomHealthChecks.GetOverlappingSiblingsAsync(
            Page, ".users-filter-form");
        Assert.That(overlaps, Is.Empty,
            $"Overlapping elements in filter form:\n{string.Join("\n", overlaps)}");
    }

    [Test]
    [Description("No preload warnings — CSS files preloaded are actually used")]
    public async Task Users_page_has_no_preload_warnings()
    {
        await Page.GotoAsync($"{BaseUrl}/management/users");
        await Page.WaitForLoadStateAsync(LoadState.NetworkIdle);

        Assert.That(_console.PreloadWarnings, Is.Empty,
            $"Preload warnings:\n{FormatEntries(_console.PreloadWarnings)}");
    }

    [Test]
    [Description("Clients page console health")]
    public async Task Clients_page_has_no_console_errors()
    {
        await Page.GotoAsync($"{BaseUrl}/management/clients");
        await Page.WaitForLoadStateAsync(LoadState.NetworkIdle);

        Assert.That(_console.Errors, Is.Empty,
            $"Console errors on /management/clients:\n{FormatEntries(_console.Errors)}");
    }

    [Test]
    [Description("Accessibility scan with axe-core (WCAG 2.1 AA)")]
    [Ignore("Requires Deque.AxeCore.Playwright configuration — enable after UI stabilizes")]
    public async Task Users_page_accessibility()
    {
        // Placeholder for axe-core scan once the UI layout issues are resolved.
        // The Deque.AxeCore.Playwright package is already referenced.
        Assert.Pass("Placeholder — enable after UI stabilizes");
    }

    private static string FormatEntries(
        IReadOnlyList<ConsoleCollector.ConsoleEntry> entries)
    {
        if (entries.Count == 0) return "(none)";
        return string.Join("\n", entries
            .Select(e => $"  [{e.Type}] {Truncate(e.Text, 200)}"));
    }

    private static string Truncate(string text, int maxLength) =>
        text.Length <= maxLength ? text : text[..maxLength] + "…";
}
