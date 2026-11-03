using System.Text.Encodings.Web;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Authorization;
using Microsoft.Extensions.DependencyInjection;
using Sufficit.Identity.Application.Branding;

namespace Sufficit.Identity.STS.Controllers;

public sealed partial class IntegrationOAuthController
{
    // Mirrors the public shell (topbar, auth card, primary action). The shell's
    // stylesheets come from the UI module, which API-only deployments do not
    // host, so the zero-specificity rules below keep the page usable without it.
    // Both the return URI and popup mode come from the protected transaction.
    private async Task<IActionResult> CompleteAuthorizationAsync(string returnUri, string provider, string status, bool popup)
    {
        if (!popup) return Redirect(ReturnLocation(returnUri, provider, status));
        Response.Headers.CacheControl = "no-store";
        Response.Headers["Referrer-Policy"] = "no-referrer";
        var connected = status == "connected";
        // A page shown to the end user, so its text follows the request
        // culture; the values come from trusted resources, not from input.
        var title = messages[connected
            ? "IntegrationCompletion.ConnectedTitle"
            : "IntegrationCompletion.FailedTitle"].Value;
        var message = messages[status switch
        {
            "connected" => "IntegrationCompletion.Connected",
            "permissions_required" => "IntegrationCompletion.PermissionsRequired",
            _ => "IntegrationCompletion.Failed",
        }].Value;
        var closeLabel = messages["IntegrationCompletion.Close"].Value;
        var closeHint = messages["IntegrationCompletion.CloseHint"].Value;
        var language = System.Globalization.CultureInfo.CurrentUICulture.Name;
        var nonce = HtmlEncoder.Default.Encode(SecurityHeadersMiddlewareExtensions.GetCspNonce(HttpContext) ?? "");
        var script = HtmlEncoder.Default.Encode(Absolute("/api/integrations/oauth/completion.js"));
        var componentStyles = HtmlEncoder.Default.Encode(Absolute("/_content/Sufficit.Blazor.UI/sufficit-ui.css"));
        var shellStyles = HtmlEncoder.Default.Encode(Absolute("/_content/Sufficit.Identity.UI/css/site.css"));
        var home = HtmlEncoder.Default.Encode(Absolute("/"));
        var services = HttpContext.RequestServices;
        var theme = services.GetService<IBrandingThemeProvider>() is { } themes
            ? await themes.GetActiveAsync(CancellationToken.None)
            : null;
        var brand = HtmlEncoder.Default.Encode(theme?.BrandName
            ?? services.GetService<ProductBrandingOptions>()?.ProductName
            ?? "Identity");
        var brandSubtitle = string.IsNullOrWhiteSpace(theme?.BrandSubtitle)
            ? ""
            : $"""<span class="brand-sub">{HtmlEncoder.Default.Encode(theme.BrandSubtitle)}</span>""";
        var brandMark = string.IsNullOrWhiteSpace(theme?.HeaderIconUrl)
            ? ""
            : $"""<img src="{HtmlEncoder.Default.Encode(theme.HeaderIconUrl)}" class="brand-mark" alt="">""";
        var connectedValue = connected ? "true" : "false";
        var statusKind = connected ? "success" : "warning";
        var statusIcon = connected
            ? "M20 6 9 17l-5-5"
            : "M12 8v5m0 3.5v.01M10.3 3.9 2.4 17.5A2 2 0 0 0 4.1 20.5h15.8a2 2 0 0 0 1.7-3L13.7 3.9a2 2 0 0 0-3.4 0Z";
        return Content($$"""
            <!doctype html><html lang="{{language}}"><head><meta charset="utf-8">
            <meta name="viewport" content="width=device-width,initial-scale=1">
            <meta name="robots" content="noindex, nofollow">
            <title>{{title}} — {{brand}}</title>
            <link rel="stylesheet" href="{{componentStyles}}">
            <link rel="stylesheet" href="{{shellStyles}}">
            <style nonce="{{nonce}}">
            :where(body) { margin: 0; background: #f6f6f7; color: #343132; font: 16px/1.5 system-ui, sans-serif; }
            :where(.page) { display: flex; flex-direction: column; min-height: 100vh; }
            :where(.topbar) { display: flex; align-items: center; height: 64px; padding: 0 24px; background: #fff; border-bottom: 1px solid #e2e1e3; }
            :where(.topbar-brand a) { display: flex; align-items: center; gap: 12px; color: inherit; text-decoration: none; }
            :where(.brand-mark) { width: 32px; height: 32px; }
            :where(.brand-wordmark) { display: inline-flex; flex-direction: column; line-height: 1.1; }
            :where(.brand-name) { font-weight: 600; }
            :where(.brand-sub) { font-size: .65rem; letter-spacing: .08em; text-transform: uppercase; }
            :where(.content) { display: flex; flex: 1; align-items: center; justify-content: center; padding: 40px 16px; }
            :where(.auth-card) { box-sizing: border-box; width: 100%; max-width: 440px; padding: 32px; background: #fff; border: 1px solid #e2e1e3; border-radius: 12px; }
            :where(.auth-card-center) { text-align: center; }
            :where(.auth-card h1) { margin: 0 0 8px; font-size: 1.5rem; font-weight: 600; }
            :where(.auth-card-subtitle) { margin: 0 0 24px; }
            :where(.sui-btn) { width: 100%; min-height: 44px; font: inherit; font-weight: 600; cursor: pointer; }
            .integration-status { display: flex; align-items: center; justify-content: center; width: 56px; height: 56px; margin: 0 auto 16px; border-radius: 50%; }
            .integration-status--success { background: var(--success-soft, #effaf2); color: var(--success, #157f3f); }
            .integration-status--warning { background: var(--warning-soft, #fff8eb); color: var(--warning, #b54708); }
            .integration-status svg { width: 28px; height: 28px; }
            .integration-close-hint { margin: 16px 0 0; color: var(--ink-muted, #58595b); font-size: .875rem; }
            </style></head><body>
            <div class="page identity-public">
            <header class="topbar"><div class="topbar-brand"><a href="{{home}}">{{brandMark}}<span class="brand-wordmark"><span class="brand-name">{{brand}}</span>{{brandSubtitle}}</span></a></div></header>
            <main class="content" data-integration-connected="{{connectedValue}}">
            <section class="auth-card auth-card-center" aria-labelledby="integration-title">
            <div class="integration-status integration-status--{{statusKind}}" aria-hidden="true"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="{{statusIcon}}"/></svg></div>
            <h1 id="integration-title">{{title}}</h1>
            <p class="auth-card-subtitle" role="status">{{message}}</p>
            <button type="button" id="close" class="sui-btn sui-btn--filled sui-btn--color-primary sui-btn--medium sui-btn--full-width">{{closeLabel}}</button>
            <p class="integration-close-hint">{{closeHint}}</p>
            </section></main></div>
            <script src="{{script}}" defer></script></body></html>
            """, "text/html; charset=utf-8");
    }

    [AllowAnonymous]
    [HttpGet("completion.js")]
    public ContentResult CompletionScript() => Content("""
        const closeButton = document.getElementById('close');
        closeButton?.addEventListener('click', () => window.close());
        if (document.querySelector('[data-integration-connected="true"]'))
            setTimeout(() => window.close(), 1200);
        """, "text/javascript; charset=utf-8");

}
