using System.Text.Encodings.Web;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Authorization;

namespace Sufficit.Identity.STS.Controllers;

public sealed partial class IntegrationOAuthController
{
    // This response must also work in API-only deployments without the Blazor UI.
    // Both the return URI and popup mode come from the protected transaction.
    private IActionResult CompleteAuthorization(string returnUri, string provider, string status, bool popup)
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
        var connectedValue = connected ? "true" : "false";
        return Content($$"""
            <!doctype html><html lang="{{language}}"><head><meta charset="utf-8">
            <meta name="viewport" content="width=device-width,initial-scale=1">
            <title>{{title}} — Sufficit</title>
            <style nonce="{{nonce}}">
            :root { color-scheme: light dark; font: 16px/1.5 system-ui, sans-serif; }
            body { margin: 0; padding: 24px; }
            main { max-width: 32rem; margin: 10vh auto; }
            h1 { font-size: 1.5rem; line-height: 1.25; }
            button { font: inherit; font-size: .875rem; padding: .65rem 1rem; cursor: pointer; }
            </style></head><body>
            <main data-integration-connected="{{connectedValue}}"><h1>{{title}}</h1><p role="status">{{message}}</p>
            <button type="button" id="close">{{closeLabel}}</button>
            <p>{{closeHint}}</p></main>
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
