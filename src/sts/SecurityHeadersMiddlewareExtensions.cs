using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
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

            // Cross-Origin-Opener-Policy: same-origin isolates the browsing
            // context, preventing cross-origin windows from script access.
            context.Response.Headers["Cross-Origin-Opener-Policy"] = "same-origin";

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
                var value = AddHumanVerificationSources(
                    options.Csp.Policy,
                    options.HumanVerification);
                if (!string.IsNullOrWhiteSpace(options.Csp.ReportUri))
                    value += $"; report-uri {options.Csp.ReportUri}";
                context.Response.Headers[header] = value;
            }

            await next();
        });

        return app;
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
