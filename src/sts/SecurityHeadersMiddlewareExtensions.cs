using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Configuration;

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
                var value = options.Csp.Policy;
                if (!string.IsNullOrWhiteSpace(options.Csp.ReportUri))
                    value += $"; report-uri {options.Csp.ReportUri}";
                context.Response.Headers[header] = value;
            }

            await next();
        });

        return app;
    }
}
