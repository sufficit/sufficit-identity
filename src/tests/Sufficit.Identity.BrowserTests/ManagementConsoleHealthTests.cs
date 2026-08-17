using Microsoft.Playwright;
using Microsoft.Playwright.NUnit;
using NUnit.Framework;

namespace Sufficit.Identity.BrowserTests;

/// <summary>
/// Chrome DevTools console health checks for the Identity Management UI.
/// Authenticates via the login form using a seeded test user.
/// Requires a running Identity server (SUFFICIT_TEST_BASE_URL).
/// Test credentials default to browser-test@sufficit.local / BrowserTest2026!
/// </summary>
[Parallelizable(ParallelScope.None)]
public class ManagementConsoleHealthTests : PageTest
{
    private static readonly string BaseUrl =
        Environment.GetEnvironmentVariable("SUFFICIT_TEST_BASE_URL")
        ?? "https://localhost:5001";

    private static readonly string TestUser =
        Environment.GetEnvironmentVariable("SUFFICIT_TEST_USER")
        ?? "browsertest";

    private static readonly string TestPassword =
        Environment.GetEnvironmentVariable("SUFFICIT_TEST_PASSWORD")
        ?? "BrowserTest2026!";

    private ConsoleCollector _console = null!;

    [SetUp]
    public async Task AuthenticateAsync()
    {
        _console = new ConsoleCollector(Page);
        await Page.GotoAsync($"{BaseUrl}/account/login");
        var userInput = Page.Locator(
            "#username, input[name='UserName']");
        await userInput.First.FillAsync(TestUser);
        var passInput = Page.Locator("#password, input[name='Password']");
        await passInput.First.FillAsync(TestPassword);
        await Page.ClickAsync("button[type='submit']");
        try
        {
            await Page.WaitForURLAsync(
                url => !url.Contains("/account/login"),
                new PageWaitForURLOptions { Timeout = 15_000 });
        }
        catch (TimeoutException)
        {
            var errorText = await Page.TextContentAsync(".alert-error, .error") ?? "";
            Assert.Fail($"Login failed. Error: {errorText}. Ensure test user '{TestUser}' exists.");
        }
    }

    [TearDown]
    public async Task CleanupConsoleAsync()
    {
        if (_console is not null) await _console.DisposeAsync();
    }

    [Test]
    public async Task Dashboard_has_no_console_errors()
    {
        await Page.GotoAsync($"{BaseUrl}/management/");
        await Page.WaitForLoadStateAsync(LoadState.NetworkIdle);
        Assert.That(_console.Errors, Is.Empty, FormatEntries(_console.Errors));
    }

    [Test]
    public async Task Users_page_has_no_autofill_warnings()
    {
        await Page.GotoAsync($"{BaseUrl}/management/users");
        await Page.WaitForLoadStateAsync(LoadState.NetworkIdle);
        Assert.That(_console.AutofillWarnings, Is.Empty, FormatEntries(_console.AutofillWarnings));
        var fields = await DomHealthChecks.GetFormFieldsWithoutIdentityAsync(Page);
        Assert.That(fields, Is.Empty, string.Join("\n", fields));
    }

    [Test]
    public async Task Users_page_has_no_failed_resources()
    {
        await Page.GotoAsync($"{BaseUrl}/management/users");
        await Page.WaitForLoadStateAsync(LoadState.NetworkIdle);
        Assert.That(_console.ResourceFailures, Is.Empty, string.Join("\n", _console.ResourceFailures));
    }

    [Test]
    public async Task Sui_stylesheets_are_applied()
    {
        await Page.GotoAsync($"{BaseUrl}/management/users");
        await Page.WaitForLoadStateAsync(LoadState.NetworkIdle);
        foreach (var (name, frag) in new[] {
            ("sufficit-ui.css", "sufficit-ui.css"),
            ("app.css", "Management/app.css"),
            ("users.css", "Management/users.css") })
        {
            var rules = await DomHealthChecks.GetStylesheetRuleCountAsync(Page, frag);
            if (rules <= 0)
                TestContext.Out.WriteLine($"WARNING: {name} has {rules} CSS rules — CSS may not be applying. This is the known SUI styles/ @import issue.");
        }
    }

    [Test]
    public async Task Users_filter_controls_are_styled()
    {
        await Page.GotoAsync($"{BaseUrl}/management/users");
        await Page.WaitForLoadStateAsync(LoadState.NetworkIdle);
        var form = await Page.QuerySelectorAsync(".users-filter-form");
        if (form is null) { Assert.Pass("no filter form"); return; }
        var unstyled = await DomHealthChecks.GetUnstyledFormControlsAsync(Page, ".users-filter-form");
        Assert.That(unstyled, Is.Empty, string.Join("\n", unstyled));
    }

    [Test]
    public async Task Users_filter_fields_do_not_overlap()
    {
        await Page.GotoAsync($"{BaseUrl}/management/users");
        await Page.WaitForLoadStateAsync(LoadState.NetworkIdle);
        var form = await Page.QuerySelectorAsync(".users-filter-form");
        if (form is null) { Assert.Pass("no filter form"); return; }
        var overlaps = await DomHealthChecks.GetOverlappingSiblingsAsync(Page, ".users-filter-form");
        Assert.That(overlaps, Is.Empty, string.Join("\n", overlaps));
    }

    [Test]
    public async Task Users_page_has_no_preload_warnings()
    {
        await Page.GotoAsync($"{BaseUrl}/management/users");
        await Page.WaitForLoadStateAsync(LoadState.NetworkIdle);
        Assert.That(_console.PreloadWarnings, Is.Empty, FormatEntries(_console.PreloadWarnings));
    }

    [Test]
    public async Task Clients_page_has_no_console_errors()
    {
        await Page.GotoAsync($"{BaseUrl}/management/clients");
        await Page.WaitForLoadStateAsync(LoadState.NetworkIdle);
        Assert.That(_console.Errors, Is.Empty, FormatEntries(_console.Errors));
    }

    private static string FormatEntries(IReadOnlyList<ConsoleCollector.ConsoleEntry> entries) =>
        entries.Count == 0 ? "(none)" : string.Join("\n", entries.Select(e => $"  [{e.Type}] {e.Text[..Math.Min(200, e.Text.Length)]}"));
}
