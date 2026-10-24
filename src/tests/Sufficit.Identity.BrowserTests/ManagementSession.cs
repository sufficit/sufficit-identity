using Microsoft.Playwright;
using NUnit.Framework;

namespace Sufficit.Identity.BrowserTests;

/// <summary>
/// Signs the seeded browser-test user into the Management console. Shared by
/// the console suites so each does not carry its own copy of the login.
/// </summary>
internal static class ManagementSession
{
    internal static readonly string BaseUrl =
        Environment.GetEnvironmentVariable("SUFFICIT_TEST_BASE_URL")
        ?? "https://localhost:5001";

    private static readonly string TestUser =
        Environment.GetEnvironmentVariable("SUFFICIT_TEST_USER")
        ?? "browsertest";

    private static readonly string TestPassword =
        Environment.GetEnvironmentVariable("SUFFICIT_TEST_PASSWORD")
        ?? "BrowserTest2026!";

    internal static async Task SignInAsync(IPage page)
    {
        TestServerProbe.EnsureServerAvailable();
        await page.GotoAsync($"{BaseUrl}/account/login");
        await page.Locator("#username, input[name='UserName']").First.FillAsync(TestUser);
        await page.Locator("#password, input[name='Password']").First.FillAsync(TestPassword);
        await page.ClickAsync("button[type='submit']");
        try
        {
            await page.WaitForURLAsync(
                url => !url.Contains("/account/login"),
                new PageWaitForURLOptions { Timeout = 15_000 });
        }
        catch (TimeoutException)
        {
            var errorText = await page.TextContentAsync(".alert-error, .error") ?? "";
            Assert.Fail($"Login failed. Error: {errorText}. Ensure test user '{TestUser}' exists.");
        }

        // The management console requires MFA (amr=mfa) to render its pages.
        // In Development the host exposes /__test__/signin, which reissues the
        // session cookie with the missing amr/acr claims. Outside Development
        // the endpoint does not exist; page-level checks then run against the
        // MFA gate instead of the full console. The fetch runs inside the page
        // so it shares the browser's cookies.
        var upgraded = await page.EvaluateAsync<bool>(@"async () => {
            const r = await fetch('/__test__/signin', {
                method: 'POST',
                headers: { 'content-type': 'application/x-www-form-urlencoded' },
                body: 'username=" + TestUser + @"&mfa=true',
                credentials: 'same-origin'
            });
            return r.ok;
        }");
        if (upgraded)
        {
            // The endpoint rewrote the auth cookie; reload so server-side
            // prerendering sees the elevated claims.
            await page.GotoAsync($"{BaseUrl}/management/");
        }
    }
}
