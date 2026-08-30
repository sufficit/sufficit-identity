using Sufficit.Identity.Application.Security;

namespace Sufficit.Identity.STS;

/// <summary>
/// HSTS policy applied by the host outside Development.
/// </summary>
public sealed class HstsOptions
{
    /// <summary>
    /// <c>max-age</c> advertised to browsers, in days.
    /// </summary>
    public int MaxAgeDays { get; init; } = 365;

    /// <summary>
    /// Extends the policy to all subdomains.
    /// </summary>
    public bool IncludeSubDomains { get; init; } = true;

    /// <summary>
    /// Opts into browser preload lists. Only meaningful together with
    /// <see cref="IncludeSubDomains"/> and a max-age of at least one year.
    /// </summary>
    public bool Preload { get; init; } = true;
}
/// <summary>
/// Explicit CORS policy for browser-based resource clients.
/// </summary>
public sealed class CorsOptions
{
    /// <summary>
    /// Enables the policy middleware. Defaults to <c>false</c> so an
    /// unconfigured public Identity deployment does not accidentally expose
    /// cross-origin APIs.
    /// </summary>
    public bool Enabled { get; init; }

    /// <summary>
    /// Exact origins allowed to call the API, including scheme and port.
    /// Wildcards and trailing paths are rejected when the policy is built.
    /// </summary>
    public List<string> AllowedOrigins { get; init; } = [];

    /// <summary>
    /// Allows browser credential mode for clients that intentionally use
    /// cookies. Bearer-only clients should leave this disabled.
    /// </summary>
    public bool AllowCredentials { get; init; }
}
public sealed class CspOptions
{
    /// <summary>
    /// Master switch for CSP emission. Default <c>true</c>. Disable only if an
    /// upstream gateway already injects a CSP.
    /// </summary>
    public bool Enabled { get; init; } = true;

    /// <summary>
    /// When <c>true</c> (default), emits <c>Content-Security-Policy-Report-Only</c>
    /// — violations are reported but NOT blocked, so a misconfigured policy
    /// cannot break the UI. Flip to <c>false</c> only after calibrating the
    /// policy against the real UI pages (see the class-level remarks).
    /// </summary>
    public bool ReportOnly { get; init; } = true;

    /// <summary>
    /// Replaces <c>'unsafe-inline'</c> in <c>style-src</c> with a per-request
    /// nonce, so an injected <c>&lt;style&gt;</c> element is blocked while the
    /// host page's own branding styles keep working (eval 2026-08-30, F-3).
    /// </summary>
    /// <remarks>
    /// <b>Opt-in (default <c>false</c>) because of one browser gap.</b> A CSP
    /// nonce authorizes <c>&lt;style&gt;</c> ELEMENTS only — it can never
    /// authorize a <c>style="…"</c> ATTRIBUTE. Those are covered by emitting
    /// <c>style-src-attr 'unsafe-inline'</c> alongside the nonce, which Chrome
    /// and Safari honor; Firefox does not implement <c>style-src-attr</c> and
    /// falls back to <c>style-src</c>, where the nonce causes
    /// <c>'unsafe-inline'</c> to be ignored per CSP Level 2. The practical
    /// effect on Firefox in enforce mode is that the few inline
    /// <c>style</c> attributes in the management pages lose their styling —
    /// cosmetic, admin-only, and invisible while
    /// <see cref="ReportOnly"/> is true.
    /// <para>Enable after confirming the browser matrix. Scripts do not need
    /// this: every script the UI loads is external, so <c>script-src</c> is
    /// already <c>'self'</c> plus the single hash for OpenIddict's form-post
    /// submit.</para>
    /// </remarks>
    public bool UseNonce { get; init; } = false;

    /// <summary>
    /// Acknowledges that running CSP in <see cref="ReportOnly"/> mode in
    /// production is a deliberate choice (e.g. during policy calibration). When
    /// false (default), the production posture check treats report-only CSP as
    /// an unresolved permissive default and — if fail-closed is on — blocks
    /// startup. Set true only if you knowingly want report-only in production.
    /// </summary>
    public bool AcknowledgeReportOnly { get; init; }

    /// <summary>
    /// The policy string. The default is tuned for a Blazor Server UI hosted
    /// same-origin with the STS: <c>connect-src</c> allows the SignalR WebSocket
    /// circuit; <c>style-src</c> allows <c>'unsafe-inline'</c> (Blazor/Bootstrap
    /// commonly require it — the calibration step should aim to remove it via
    /// nonces/hashes); <c>img-src</c> admits the same-origin UI and the
    /// Sufficit avatar endpoint used by authenticated shells;
    /// <c>frame-ancestors 'none'</c> reinforces
    /// <c>X-Frame-Options: DENY</c>. Adjust per environment as needed.
    /// </summary>
    public string Policy { get; init; } =
        "default-src 'self'; " +
        "script-src 'self'; " +
        "style-src 'self' 'unsafe-inline'; " +
        "img-src 'self' data:; " +
        // 'self' covers the same-origin SignalR WebSocket upgrade — no need
        // for broad wss:/ws: wildcards that would allow XSS exfil to any host.
        "connect-src 'self'; " +
        "frame-ancestors 'none'; " +
        "base-uri 'self'; " +
        "form-action 'self'";

    /// <summary>
    /// Optional <c>report-uri</c> (or <c>report-to</c>) endpoint appended to
    /// the policy so a violation collector can receive reports during the
    /// report-only calibration phase. Null/empty = no <c>report-uri</c>
    /// directive emitted.
    /// </summary>
    public string? ReportUri { get; init; }
}
/// <summary>
/// Publication policy for the OpenAPI document and Swagger UI.
/// </summary>
/// <remarks>
/// The contract used to be published unconditionally, including in
/// Production. Both endpoints are anonymous, so that handed any passer-by a
/// complete inventory of the management, SCIM, provisioning and vault
/// surfaces — every route, verb and DTO — which turns reconnaissance against
/// the authorization-gated endpoints into a reading exercise. Publishing is
/// still supported, but it is now a decision a deployment makes rather than
/// the default.
/// </remarks>
public sealed class SwaggerOptions
{
    /// <summary>
    /// Publishes the OpenAPI document and Swagger UI. When left unset
    /// (default), the contract is published only in Development. Set to
    /// <c>true</c> to publish in every environment, or <c>false</c> to never
    /// publish it.
    /// </summary>
    public bool? Enabled { get; init; }
}
