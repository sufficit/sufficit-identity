using System.Net;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.AspNetCore.WebUtilities;
using Sufficit.Identity.STS;
using Sufficit.Identity.Tests.Infrastructure;
using Xunit;

namespace Sufficit.Identity.Tests;

/// <summary>
/// Validates the Content-Security-Policy header emission (eval M1 / plan item
/// 2.1). The header middleware (<see cref="Sufficit.Identity.STS.SecurityHeadersMiddlewareExtensions.UseSufficitSecurityHeaders"/>)
/// is shared between the composition host (<c>Program.cs</c>) and the test
/// factory, so these tests exercise the SAME code the host runs — they do not
/// re-implement it. They assert header PRESENCE and VALUE; they do NOT validate
/// the policy against the real Blazor UI DOM (that calibration is an operational
/// step in the embedded public UI — see <see cref="Sufficit.Identity.STS.CspOptions"/>
/// class doc).
/// </summary>
[Collection(StsCollection.Name)]
public sealed class CspHeaderTests
{
    private readonly SufficitIdentityTestFactory _factory;

    public CspHeaderTests(SufficitIdentityTestFactory factory) => _factory = factory;

    [Fact]
    public async Task Default_config_emits_csp_report_only_header_on_every_response()
    {
        // Default CspOptions: Enabled=true, ReportOnly=true. The header must be
        // present on a plain JSON response (e.g. an error from /connect/token)
        // — the middleware is a single unconditional pass, not gated on
        // Content-Type, so CSP rides along on every response.
        var client = _factory.CreateClient();

        using var response = await client.PostAsync("/connect/token",
            new FormUrlEncodedContent(new Dictionary<string, string>
            {
                ["grant_type"] = "client_credentials",
            }));

        Assert.True(response.Headers.TryGetValues(
            "Content-Security-Policy-Report-Only", out var reportOnlyValues));
        var csp = Assert.Single(reportOnlyValues);

        // The default policy (CspOptions.Policy) must be emitted verbatim.
        Assert.Contains("default-src 'self'", csp, StringComparison.Ordinal);
        Assert.Contains("script-src 'self'", csp, StringComparison.Ordinal);
        Assert.Contains(
            "img-src 'self' data:",
            csp,
            StringComparison.Ordinal);
        // No avatar origin is configured in this fixture, so the directive must
        // stay closed. The header is composed from the same setting that gates
        // avatar rendering; an origin present in one and absent from the other
        // renders a broken image and reports nothing, which looks exactly like
        // an account with no avatar and so never gets filed as a bug.
        Assert.DoesNotContain("img-src 'self' data: https:", csp, StringComparison.Ordinal);
        Assert.DoesNotContain("img-src *", csp, StringComparison.Ordinal);
        Assert.Contains("connect-src 'self'", csp, StringComparison.Ordinal);
        // Tightened: no broad wss:/ws: wildcards (XSS exfil channel). 'self'
        // covers the same-origin SignalR WebSocket upgrade.
        Assert.DoesNotContain("wss:", csp, StringComparison.Ordinal);
        // frame-ancestors 'none' reinforces X-Frame-Options: DENY (eval M1
        // acceptance criterion).
        Assert.Contains("frame-ancestors 'none'", csp, StringComparison.Ordinal);
        Assert.Contains("form-action 'self'", csp, StringComparison.Ordinal);
    }

    /// <summary>
    /// The logout confirmation page must be allowed to land on the relying
    /// party.
    /// </summary>
    /// <remarks>
    /// Browsers apply <c>form-action</c> to the whole redirect chain, not just
    /// the form's action attribute. The form posts same-origin to
    /// <c>/connect/endsession</c>, which <c>'self'</c> permits — but the 302 to
    /// the RP's post-logout URI is cross-origin, so <c>'self'</c> alone blocks
    /// the submission before it is ever sent. Nothing reaches the server and
    /// nothing appears in its log; the button simply does nothing.
    /// </remarks>
    [Fact]
    public async Task Logout_page_allows_form_action_to_the_registered_post_logout_uri()
    {
        var client = _factory.CreateClient(new WebApplicationFactoryClientOptions
        {
            AllowAutoRedirect = false,
        });

        using var response = await client.GetAsync(
            "/account/logout?post_logout_redirect_uri="
                + Uri.EscapeDataString(TestDataSeeder.AuthorizationCodePostLogoutRedirectUri));

        var csp = string.Join(' ', response.Headers.GetValues("Content-Security-Policy-Report-Only"));
        var expected = new Uri(TestDataSeeder.AuthorizationCodePostLogoutRedirectUri)
            .GetLeftPart(UriPartial.Path);

        Assert.Contains(expected, csp, StringComparison.Ordinal);
    }

    /// <summary>
    /// The query string is caller-controlled, so a value nobody registered must
    /// not widen the policy to wherever a crafted link points.
    /// </summary>
    [Fact]
    public async Task Logout_page_ignores_an_unregistered_post_logout_uri()
    {
        var client = _factory.CreateClient(new WebApplicationFactoryClientOptions
        {
            AllowAutoRedirect = false,
        });

        using var response = await client.GetAsync(
            "/account/logout?post_logout_redirect_uri="
                + Uri.EscapeDataString("https://nao-registrado.example/callback"));

        var csp = string.Join(' ', response.Headers.GetValues("Content-Security-Policy-Report-Only"));

        Assert.DoesNotContain("nao-registrado.example", csp, StringComparison.Ordinal);
    }

    [Fact]
    public async Task X_Frame_options_denied_is_emitted_alongside_csp()
    {
        // Regression guard: X-Frame-Options: DENY was the pre-existing click-
        // jacking mitigation; CSP frame-ancestors 'none' reinforces it but does
        // not replace it (older browsers). Both must coexist.
        var client = _factory.CreateClient();

        using var response = await client.GetAsync("/health");

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        Assert.Equal("DENY", response.Headers.GetValues("X-Frame-Options").FirstOrDefault());
        Assert.True(response.Headers.Contains("Content-Security-Policy-Report-Only"));
        var permissions = Assert.Single(
            response.Headers.GetValues("Permissions-Policy"));
        Assert.Contains(
            "publickey-credentials-get=(self)",
            permissions,
            StringComparison.Ordinal);
        Assert.Contains(
            "publickey-credentials-create=(self)",
            permissions,
            StringComparison.Ordinal);
    }

    [Fact]
    public async Task Popup_marker_uses_a_COOP_policy_that_preserves_the_opener()
    {
        var client = _factory.CreateClient();

        using var response = await client.GetAsync("/health?launch_mode=popup");

        Assert.Equal(
            "same-origin-allow-popups",
            response.Headers.GetValues("Cross-Origin-Opener-Policy").Single());
    }

    [Fact]
    public async Task Popup_marker_inside_a_login_return_url_preserves_the_opener()
    {
        var client = _factory.CreateClient();

        using var response = await client.GetAsync(
            "/health?ReturnUrl=%2Fconnect%2Fauthorize%3Flaunch_mode%3Dpopup");

        Assert.Equal(
            "same-origin-allow-popups",
            response.Headers.GetValues("Cross-Origin-Opener-Policy").Single());
    }

    [Fact]
    public async Task Device_return_url_without_popup_marker_does_not_throw()
    {
        var client = _factory.CreateClient();

        using var response = await client.GetAsync(
            "/health?ReturnUrl=%2Fconnect%2Fdevice%3Fuser_code%3D4765-2829-4247");

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        Assert.Equal(
            "same-origin",
            response.Headers.GetValues("Cross-Origin-Opener-Policy").Single());
    }

    [Fact]
    public async Task Report_uri_is_appended_when_configured()
    {
        // Isolated factory: overlay a ReportUri and assert it is appended as a
        // `report-uri <value>` directive. Uses CreateIsolated so the shared
        // fixture's config is untouched for the other tests in the collection.
        using var factory = SufficitIdentityTestFactory.CreateIsolated(new Dictionary<string, string?>
        {
            ["Sufficit:Identity:Csp:ReportUri"] = "https://collector.tests.local/csp",
        });
        await ((IAsyncLifetime)factory).InitializeAsync();

        var client = factory.CreateClient();
        using var response = await client.GetAsync("/health");

        Assert.True(response.Headers.TryGetValues(
            "Content-Security-Policy-Report-Only", out var values));
        var csp = Assert.Single(values);
        Assert.Contains("report-uri https://collector.tests.local/csp", csp, StringComparison.Ordinal);
    }

    [Fact]
    public void Form_post_policy_uses_a_script_hash_and_the_validated_callback()
    {
        var options = new SufficitIdentityOptions
        {
            Csp = new CspOptions
            {
                Enabled = true,
                ReportOnly = false,
                ReportUri = "/security/csp-report",
            },
        };

        var policy = SecurityHeadersMiddlewareExtensions
            .BuildFormPostContentSecurityPolicy(
                options,
                "https://client.example/callback?source=identity#ignored");
        var scriptDirective = policy
            .Split(';', StringSplitOptions.TrimEntries)
            .Single(value => value.StartsWith("script-src ", StringComparison.Ordinal));

        Assert.Contains(
            SecurityHeadersMiddlewareExtensions.OpenIddictFormPostScriptHash,
            scriptDirective,
            StringComparison.Ordinal);
        Assert.DoesNotContain("'unsafe-inline'", scriptDirective, StringComparison.Ordinal);
        Assert.Contains(
            "form-action 'self' https://client.example/callback",
            policy,
            StringComparison.Ordinal);
        Assert.DoesNotContain("source=identity", policy, StringComparison.Ordinal);
        Assert.Contains("report-uri /security/csp-report", policy, StringComparison.Ordinal);
    }

    [Fact]
    public void Nonce_policy_replaces_unsafe_inline_and_scopes_attributes()
    {
        // F-3 (eval 2026-08-30): with UseNonce on, style-src must carry the
        // nonce and MUST NOT keep 'unsafe-inline' — CSP Level 2 ignores
        // 'unsafe-inline' on a directive that has a nonce, so leaving it would
        // be decorative. Inline style ATTRIBUTES cannot take a nonce, so they
        // move to the narrowly scoped style-src-attr.
        var options = new SufficitIdentityOptions
        {
            Csp = new CspOptions { Enabled = true, UseNonce = true },
        };

        var policy = SecurityHeadersMiddlewareExtensions
            .BuildContentSecurityPolicy(options, "TESTNONCEVALUE");
        var styleDirective = policy
            .Split(';', StringSplitOptions.TrimEntries)
            .Single(value => value.StartsWith("style-src ", StringComparison.Ordinal));

        Assert.Contains("'nonce-TESTNONCEVALUE'", styleDirective, StringComparison.Ordinal);
        Assert.DoesNotContain("'unsafe-inline'", styleDirective, StringComparison.Ordinal);
        Assert.Contains("style-src-attr 'unsafe-inline'", policy, StringComparison.Ordinal);
        // script-src is untouched: every script the UI loads is external.
        Assert.DoesNotContain("'nonce-TESTNONCEVALUE'", policy
            .Split(';', StringSplitOptions.TrimEntries)
            .Single(value => value.StartsWith("script-src ", StringComparison.Ordinal)),
            StringComparison.Ordinal);
    }

    [Fact]
    public void Policy_without_a_nonce_keeps_the_compatible_unsafe_inline_default()
    {
        var options = new SufficitIdentityOptions
        {
            Csp = new CspOptions { Enabled = true, UseNonce = false },
        };

        var policy = SecurityHeadersMiddlewareExtensions
            .BuildContentSecurityPolicy(options);
        var styleDirective = policy
            .Split(';', StringSplitOptions.TrimEntries)
            .Single(value => value.StartsWith("style-src ", StringComparison.Ordinal));

        Assert.Contains("'unsafe-inline'", styleDirective, StringComparison.Ordinal);
        Assert.DoesNotContain("nonce-", policy, StringComparison.Ordinal);
        Assert.DoesNotContain("style-src-attr", policy, StringComparison.Ordinal);
    }

    [Fact]
    public async Task Enabled_nonce_reaches_the_response_header_and_varies_per_request()
    {
        // The nonce is only useful if it is unpredictable per response; a
        // constant would authorize an injected <style> on every later request.
        using var factory = SufficitIdentityTestFactory.CreateIsolated(
            new Dictionary<string, string?>
            {
                ["Sufficit:Identity:Csp:UseNonce"] = "true",
            });
        var client = factory.CreateClient();

        var first = await client.GetAsync("/.well-known/openid-configuration");
        var second = await client.GetAsync("/.well-known/openid-configuration");

        var firstNonce = ExtractStyleNonce(first);
        var secondNonce = ExtractStyleNonce(second);

        Assert.NotNull(firstNonce);
        Assert.NotNull(secondNonce);
        Assert.NotEqual(firstNonce, secondNonce);
    }

    private static string? ExtractStyleNonce(HttpResponseMessage response)
    {
        var header = response.Headers
            .TryGetValues("Content-Security-Policy-Report-Only", out var reportOnly)
            ? reportOnly.FirstOrDefault()
            : response.Headers.TryGetValues("Content-Security-Policy", out var enforced)
                ? enforced.FirstOrDefault()
                : null;
        if (header is null)
        {
            return null;
        }

        var match = System.Text.RegularExpressions.Regex.Match(
            header,
            @"style-src [^;]*'nonce-([A-Za-z0-9+/=]+)'");
        return match.Success ? match.Groups[1].Value : null;
    }

    [Fact]
    public async Task Form_post_authorization_response_receives_the_tailored_policy()
    {
        var client = _factory.CreateClient(
            new WebApplicationFactoryClientOptions { AllowAutoRedirect = false });
        await TestOnlyEndpoints.SignInAsync(client, TestDataSeeder.DefaultUsername);
        var (_, challenge) = Pkce.CreatePair();
        var query = new Dictionary<string, string?>
        {
            ["response_type"] = "code",
            ["response_mode"] = "form_post",
            ["client_id"] = TestDataSeeder.AuthorizationCodeClientId,
            ["redirect_uri"] = TestDataSeeder.AuthorizationCodeRedirectUri,
            ["scope"] = "openid profile",
            ["state"] = Guid.NewGuid().ToString("N"),
            ["code_challenge"] = challenge,
            ["code_challenge_method"] = "S256",
        };

        using var response = await client.GetAsync(
            QueryHelpers.AddQueryString("/connect/authorize", query));

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        var policy = Assert.Single(response.Headers.GetValues(
            "Content-Security-Policy-Report-Only"));
        Assert.Contains(
            SecurityHeadersMiddlewareExtensions.OpenIddictFormPostScriptHash,
            policy,
            StringComparison.Ordinal);
        Assert.Contains(
            $"form-action 'self' {TestDataSeeder.AuthorizationCodeRedirectUri}",
            policy,
            StringComparison.Ordinal);
        Assert.Contains(
            "<script>document.form.submit();</script>",
            await response.Content.ReadAsStringAsync(),
            StringComparison.Ordinal);
    }

    [Fact]
    public async Task Report_only_false_switches_header_to_enforce()
    {
        // The operational flip: ReportOnly=false emits the ENFORCE header
        // (Content-Security-Policy) instead of the Report-Only one. An operator
        // does this only after calibrating Policy against the real UI — here we
        // just prove the switch routes to the right header name.
        using var factory = SufficitIdentityTestFactory.CreateIsolated(new Dictionary<string, string?>
        {
            ["Sufficit:Identity:Csp:ReportOnly"] = "false",
        });
        await ((IAsyncLifetime)factory).InitializeAsync();

        var client = factory.CreateClient();
        using var response = await client.GetAsync("/health");

        // Enforce header present, Report-Only header absent.
        Assert.True(response.Headers.Contains("Content-Security-Policy"));
        Assert.False(response.Headers.Contains("Content-Security-Policy-Report-Only"));
    }

    [Fact]
    public async Task Disabled_csp_omits_the_header_entirely()
    {
        // Csp.Enabled=false is the escape hatch for when an upstream gateway
        // already injects a CSP. The other baseline headers (X-Frame-Options
        // etc.) MUST still be emitted — only CSP is suppressed.
        using var factory = SufficitIdentityTestFactory.CreateIsolated(new Dictionary<string, string?>
        {
            ["Sufficit:Identity:Csp:Enabled"] = "false",
        });
        await ((IAsyncLifetime)factory).InitializeAsync();

        var client = factory.CreateClient();
        using var response = await client.GetAsync("/health");

        Assert.False(response.Headers.Contains("Content-Security-Policy"));
        Assert.False(response.Headers.Contains("Content-Security-Policy-Report-Only"));
        // Baseline headers still present.
        Assert.Equal("DENY", response.Headers.GetValues("X-Frame-Options").FirstOrDefault());
    }

    [Theory]
    [InlineData(
        "GoogleRecaptchaV2",
        "https://www.google.com",
        "https://www.gstatic.com")]
    [InlineData(
        "Turnstile",
        "https://challenges.cloudflare.com",
        "https://challenges.cloudflare.com")]
    public async Task Human_verification_adds_provider_origins_to_csp(
        string provider,
        string frameOrigin,
        string scriptOrigin)
    {
        using var factory = SufficitIdentityTestFactory.CreateIsolated(
            new Dictionary<string, string?>
            {
                ["Sufficit:Identity:HumanVerification:Enabled"] = "true",
                ["Sufficit:Identity:HumanVerification:Provider"] = provider,
                ["Sufficit:Identity:HumanVerification:SiteKey"] = "test-site-key",
                ["Sufficit:Identity:HumanVerification:SecretKey"] = "test-secret-key",
            });
        await ((IAsyncLifetime)factory).InitializeAsync();

        var client = factory.CreateClient();
        using var response = await client.GetAsync("/health");

        var csp = Assert.Single(response.Headers.GetValues(
            "Content-Security-Policy-Report-Only"));
        Assert.Contains($"script-src 'self'", csp, StringComparison.Ordinal);
        Assert.Contains(scriptOrigin, csp, StringComparison.Ordinal);
        Assert.Contains("frame-src", csp, StringComparison.Ordinal);
        Assert.Contains(frameOrigin, csp, StringComparison.Ordinal);
    }
}
