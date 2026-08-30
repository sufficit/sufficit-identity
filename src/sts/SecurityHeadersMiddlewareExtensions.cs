using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.WebUtilities;
using Microsoft.Extensions.Configuration;
using Sufficit.Identity.Application.Security;

namespace Sufficit.Identity.STS;

/// <summary>
/// Pipeline extensions that emit the STS's baseline security response headers
/// (<c>X-Content-Type-Options</c>, <c>Referrer-Policy</c>, <c>X-Frame-Options</c>
/// and <c>Content-Security-Policy</c>). Extracted into the STS module — instead
/// of living inline in the composition host's <c>Program.cs</c> — so the same
/// code runs in the integration test factory (which does not reproduce
/// <c>Program.cs</c> line-for-line; see <c>SufficitIdentityTestFactory</c>).
/// Mirrors the <c>UseSufficitIdentityManagementEndpoints</c> pattern in the
/// management module.
/// </summary>
public static class SecurityHeadersMiddlewareExtensions
{
    // OpenIddict 7.6 emits exactly this inline script for response_mode=form_post:
    // document.form.submit();. A CSP hash authorizes that immutable script
    // without enabling the much broader 'unsafe-inline' source expression.
    internal const string OpenIddictFormPostScriptHash =
        "'sha256-j7OoGArf6XW6YY4cAyS3riSSvrJRqpSi1fOF9vQ5SrI='";

    /// <summary>
    /// Default Permissions-Policy: deny every capability. The STS UI (login,
    /// consent, device, manage) needs none of the browser capabilities listed
    /// below. An operator adding a page that requires a specific permission
    /// can override the entire header via reverse-proxy or a future config knob.
    /// </summary>
    private const string PermissionsPolicyDefault =
        "accelerometer=(), autoplay=(), camera=(), cross-origin-isolated=(), " +
        "display-capture=(), encrypted-media=(), fullscreen=(), geolocation=(), " +
        "gyroscope=(), keyboard-map=(), magnetometer=(), microphone=(), " +
        "midi=(), payment=(), picture-in-picture=(), " +
        "publickey-credentials-get=(self), publickey-credentials-create=(self), " +
        "screen-wake-lock=(), sync-xhr=(), usb=(), xr-spatial-tracking=()";

    /// <summary>
    /// Emits <c>X-Content-Type-Options: nosniff</c>,
    /// <c>Referrer-Policy: strict-origin-when-cross-origin</c>,
    /// <c>X-Frame-Options: DENY</c>, and — when <see cref="CspOptions.Enabled"/>
    /// is true — a <c>Content-Security-Policy</c> (or
    /// <c>Content-Security-Policy-Report-Only</c>) header built from
    /// <c>Sufficit:Identity:Csp</c>. The CSP is appended to every response
    /// regardless of Content-Type: browsers ignore it on non-HTML responses, so
    /// this keeps the middleware a single unconditional pass.
    /// </summary>
    public static IApplicationBuilder UseSufficitSecurityHeaders(
        this IApplicationBuilder app,
        IConfiguration configuration,
        string configurationSection = "Sufficit:Identity")
    {
        var options = configuration
            .GetSection(configurationSection)
            .Get<SufficitIdentityOptions>() ?? new SufficitIdentityOptions();

        return UseSufficitSecurityHeaders(app, options);
    }

    /// <summary>
    /// Overload accepting the already-bound <see cref="SufficitIdentityOptions"/>
    /// directly — used by hosts that have already bound the section once (e.g.
    /// <c>Program.cs</c> binds it for rate limiting / HSTS too) to avoid a second
    /// bind pass, and by the integration test factory which constructs the
    /// options from in-memory configuration.
    /// </summary>
    public static IApplicationBuilder UseSufficitSecurityHeaders(
        this IApplicationBuilder app,
        SufficitIdentityOptions options)
    {
        app.Use(async (context, next) =>
        {
            context.Response.Headers["X-Content-Type-Options"] = "nosniff";
            context.Response.Headers["Referrer-Policy"] = "strict-origin-when-cross-origin";
            context.Response.Headers["X-Frame-Options"] = "DENY";

            // L7: modern cross-origin isolation / capabilities headers expected
            // on an IdP in 2026. These are static and safe for an STS that does
            // not embed third-party content or expose cross-origin resources.
            //
            // Permissions-Policy: deny everything by default. The STS UI needs
            // no camera, microphone, geolocation, USB, etc. An operator adding
            // a page that needs a specific permission can override via config.
            context.Response.Headers["Permissions-Policy"] = PermissionsPolicyDefault;

            // Cross-Origin-Opener-Policy: same-origin isolates normal pages.
            // An explicitly requested popup flow uses the compatible policy
            // so the caller can retain its WindowProxy through the Identity
            // login/consent redirects and receive the terminal postMessage.
            context.Response.Headers["Cross-Origin-Opener-Policy"] =
                IsPopupLaunchRequest(context.Request)
                    ? "same-origin-allow-popups"
                    : "same-origin";

            // Cross-Origin-Resource-Policy: same-origin prevents the STS's
            // static resources from being loaded cross-origin (noauth images,
            // CSS, JS) by unrelated sites.
            context.Response.Headers["Cross-Origin-Resource-Policy"] = "same-origin";

            // Content-Security-Policy (eval M1). Ships in Report-Only mode by
            // default (CspOptions.ReportOnly=true) so a misconfigured policy
            // never breaks the UI — violations are reported, not blocked. An
            // operator flips to enforce (ReportOnly=false) only after
            // calibrating the policy against the real UI pages; see the
            // CspOptions class doc for the rollout model.
            if (options.Csp.Enabled)
            {
                var header = options.Csp.ReportOnly
                    ? "Content-Security-Policy-Report-Only"
                    : "Content-Security-Policy";

                // The nonce must exist BEFORE the response is rendered, since
                // the host page reads it while emitting its <style> elements.
                // Publishing it on HttpContext.Items keeps the UI free of a
                // dependency on this module's types (eval 2026-08-30, F-3).
                var nonce = options.Csp.UseNonce ? CreateNonce() : null;
                if (nonce is not null)
                {
                    context.Items[CspNonceItemKey] = nonce;
                }

                context.Response.Headers[header] =
                    BuildContentSecurityPolicy(options, nonce);
            }

            await next();
        });

        return app;
    }

    private static bool IsPopupLaunchRequest(HttpRequest request)
    {
        if (IsPopupLaunchMode(request.Query["launch_mode"]))
        {
            return true;
        }

        // Login and external-provider pages carry the original protocol URL
        // in ReturnUrl/returnUrl. Preserve the popup capability while that
        // nested URL is being followed; otherwise COOP would sever opener
        // before the callback can return to the original window.
        foreach (var name in new[] { "ReturnUrl", "returnUrl" })
        {
            var returnUrl = request.Query[name].ToString();
            var separator = returnUrl.IndexOf('?');
            if (separator < 0)
            {
                continue;
            }

            var query = QueryHelpers.ParseQuery(returnUrl[separator..]);
            if (query.TryGetValue("launch_mode", out var launchMode)
                && IsPopupLaunchMode(launchMode.ToString()))
            {
                return true;
            }
        }

        return false;
    }

    private static bool IsPopupLaunchMode(string? value) =>
        string.Equals(value, "popup", StringComparison.OrdinalIgnoreCase);

    /// <summary>
    /// <c>HttpContext.Items</c> key carrying the per-request CSP nonce when
    /// <see cref="CspOptions.UseNonce"/> is enabled. The key itself lives in the
    /// dependency-free contract project so the UI can read the nonce without
    /// referencing the STS assembly.
    /// </summary>
    internal const string CspNonceItemKey = CspNonce.ItemKey;

    /// <summary>
    /// Returns the CSP nonce for the current request, or <c>null</c> when
    /// nonce-based CSP is disabled. A host page emits it as
    /// <c>nonce="@value"</c> on every inline <c>&lt;style&gt;</c> it renders;
    /// when this returns null the policy still carries <c>'unsafe-inline'</c>,
    /// so omitting the attribute is correct rather than merely tolerated.
    /// </summary>
    public static string? GetCspNonce(HttpContext context)
    {
        ArgumentNullException.ThrowIfNull(context);
        return CspNonce.From(context.Items);
    }

    // 128 bits, base64. CSP only requires the value be unpredictable per
    // response; base64 keeps it directly usable as a source expression.
    private static string CreateNonce() =>
        Convert.ToBase64String(
            System.Security.Cryptography.RandomNumberGenerator.GetBytes(16));

    internal static string BuildContentSecurityPolicy(
        SufficitIdentityOptions options,
        string? nonce = null)
    {
        var value = AddHumanVerificationSources(
            options.Csp.Policy,
            options.HumanVerification);

        if (!string.IsNullOrEmpty(nonce))
        {
            value = ApplyStyleNonce(value, nonce);
        }

        if (!string.IsNullOrWhiteSpace(options.Csp.ReportUri))
        {
            value += $"; report-uri {options.Csp.ReportUri}";
        }

        return value;
    }

    /// <summary>
    /// Swaps <c>'unsafe-inline'</c> out of <c>style-src</c> for the request
    /// nonce and re-grants it, narrowly, to <c>style-src-attr</c>. Keeping
    /// <c>'unsafe-inline'</c> alongside a nonce would be pointless — CSP Level 2
    /// says a directive carrying a nonce or hash ignores <c>'unsafe-inline'</c>
    /// entirely — so it is removed rather than left as decoration.
    /// </summary>
    private static string ApplyStyleNonce(string policy, string nonce)
    {
        var directives = policy
            .Split(';', StringSplitOptions.RemoveEmptyEntries
                | StringSplitOptions.TrimEntries)
            .ToList();
        var index = directives.FindIndex(value =>
            value.Equals("style-src", StringComparison.OrdinalIgnoreCase)
            || value.StartsWith("style-src ", StringComparison.OrdinalIgnoreCase));

        if (index < 0)
        {
            // No style-src to harden: the deployment replaced the policy and
            // owns its own style sourcing. Do not invent a directive for it.
            return policy;
        }

        var sources = directives[index]
            .Split(' ', StringSplitOptions.RemoveEmptyEntries)
            .Skip(1)
            .Where(source => !source.Equals(
                "'unsafe-inline'",
                StringComparison.OrdinalIgnoreCase))
            .ToList();
        sources.Add($"'nonce-{nonce}'");
        directives[index] = "style-src " + string.Join(' ', sources);

        // Inline style ATTRIBUTES cannot carry a nonce, so they keep the
        // targeted relaxation. Only added when the policy does not already
        // state its own style-src-attr.
        if (!directives.Any(value =>
            value.Equals("style-src-attr", StringComparison.OrdinalIgnoreCase)
            || value.StartsWith(
                "style-src-attr ",
                StringComparison.OrdinalIgnoreCase)))
        {
            directives.Add("style-src-attr 'unsafe-inline'");
        }

        return string.Join("; ", directives);
    }

    internal static string BuildFormPostContentSecurityPolicy(
        SufficitIdentityOptions options,
        string redirectUri)
    {
        var policy = BuildContentSecurityPolicy(options);
        if (!Uri.TryCreate(redirectUri, UriKind.Absolute, out var uri)
            || (!string.Equals(uri.Scheme, Uri.UriSchemeHttp, StringComparison.OrdinalIgnoreCase)
                && !string.Equals(uri.Scheme, Uri.UriSchemeHttps, StringComparison.OrdinalIgnoreCase))
            || !string.IsNullOrEmpty(uri.UserInfo))
        {
            return policy;
        }

        // context.RedirectUri has already passed OpenIddict's registered URI
        // validation when this method is called by the form-post handler. Strip
        // query/fragment because they are not valid CSP source-expression data.
        var action = uri.GetLeftPart(UriPartial.Path);
        return AddSources(
            AddSources(
                policy,
                "script-src",
                OpenIddictFormPostScriptHash),
            "form-action",
            action);
    }

    private static string AddHumanVerificationSources(
        string policy,
        HumanVerificationOptions verification)
    {
        if (!verification.Enabled)
        {
            return policy;
        }

        return verification.Provider switch
        {
            HumanVerificationProvider.GoogleRecaptchaV2 => AddSources(
                AddSources(
                    AddSources(
                        policy,
                        "script-src",
                        "https://www.google.com",
                        "https://www.gstatic.com"),
                    "frame-src",
                    "https://www.google.com",
                    "https://recaptcha.google.com"),
                "connect-src",
                "https://www.google.com"),
            HumanVerificationProvider.Turnstile => AddSources(
                AddSources(
                    AddSources(
                        policy,
                        "script-src",
                        "https://challenges.cloudflare.com"),
                    "frame-src",
                    "https://challenges.cloudflare.com"),
                "connect-src",
                "https://challenges.cloudflare.com"),
            _ => policy,
        };
    }

    private static string AddSources(
        string policy,
        string directiveName,
        params string[] sources)
    {
        var directives = policy
            .Split(';', StringSplitOptions.RemoveEmptyEntries
                | StringSplitOptions.TrimEntries)
            .ToList();
        var index = directives.FindIndex(value =>
            value.Equals(directiveName, StringComparison.OrdinalIgnoreCase)
            || value.StartsWith(
                directiveName + " ",
                StringComparison.OrdinalIgnoreCase));

        if (index < 0)
        {
            directives.Add($"{directiveName} {string.Join(' ', sources)}");
        }
        else
        {
            var existing = directives[index]
                .Split(' ', StringSplitOptions.RemoveEmptyEntries)
                .Skip(1)
                .ToHashSet(StringComparer.OrdinalIgnoreCase);
            var additions = sources.Where(existing.Add).ToArray();
            if (additions.Length > 0)
            {
                directives[index] += " " + string.Join(' ', additions);
            }
        }

        return string.Join("; ", directives);
    }
}
