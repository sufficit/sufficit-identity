using System.Collections.Immutable;
using System.Security.Claims;
using System.Text;
using System.Text.Encodings.Web;
using System.Text.Json;
using Microsoft.AspNetCore;
using Microsoft.AspNetCore.Antiforgery;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.WebUtilities;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Logging;
using Microsoft.IdentityModel.Tokens;
using OpenIddict.Abstractions;
using OpenIddict.Server.AspNetCore;
using Sufficit.Identity.Application.Branding;
using Sufficit.Identity.Core.Entities;
using Sufficit.Identity.STS.Consent;
using static OpenIddict.Abstractions.OpenIddictConstants;

namespace Sufficit.Identity.STS.Controllers;

public partial class AuthorizationController
{
    // -----------------------------------------------------------------------
    // /connect/endsession — OIDC RP-Initiated Logout 1.0.
    //
    // The GET handler forwards the endsession request to the UI confirmation
    // page hosted by Sufficit.Identity.UI (Blazor Server, /Account/Logout).
    // The user confirms there and POSTs back here to perform the actual
    // sign-out, which triggers the OpenIddict SignOut and the optional
    // post_logout_redirect_uri redirect.
    // -----------------------------------------------------------------------
    [HttpGet("~/connect/logout")]
    [HttpGet("~/connect/endsession")]
    public IActionResult Logout()
    {
        // Read the end session request parsed by OpenIddict (if present).
        var request = HttpContext.GetOpenIddictServerRequest();

        // Forward the parameters to the UI confirmation page as query string.
        // Keep the internal return marker small. The original implementation
        // copied Request.QueryString here and then forwarded id_token_hint,
        // post_logout_redirect_uri and state again below. Even without that
        // duplication, forwarding a normal JWT in this intermediate Location
        // header can exceed nginx's upstream response buffer and turn a valid
        // logout into a 502. The protocol request has already been validated
        // by OpenIddict, and the confirmation UI only needs the short
        // post-logout target and state to continue the flow.
        var queryParams = new Dictionary<string, string?>
        {
            ["ReturnUrl"] = Request.Path
        };
        if (request?.PostLogoutRedirectUri is { } postLogoutRedirectUri)
            queryParams["post_logout_redirect_uri"] = postLogoutRedirectUri;
        if (request?.State is { } state)
            queryParams["state"] = state;

        return Redirect(QueryHelpers.AddQueryString("/account/logout", queryParams));
    }

    [ActionName(nameof(Logout))]
    [HttpPost("~/connect/logout")]
    [HttpPost("~/connect/endsession")]
    public async Task<IActionResult> LogoutPost()
    {
        // The actual sign-out, triggered after the user confirms in the UI page.
        // CSRF (#N2): validate the antiforgery token server-side — the STS host
        // is API-only and does NOT register the MVC [ValidateAntiForgeryToken]
        // auto-filter, so the Blazor EditForm/AntiforgeryToken component alone
        // is NOT sufficient. A malicious page could otherwise POST here riding
        // the victim's cookie and force a logout (lower-impact than #N1's
        // consent-grant CSRF, but same root cause). Mirrors the consent POST
        // and DeviceController.Verify patterns.
        try
        {
            await _antiforgery.ValidateRequestAsync(HttpContext);
        }
        catch (AntiforgeryValidationException ex)
        {
            // The token is bound to the authenticated principal, so a
            // confirmation page that outlived its session fails this check:
            // a second click, the back button, or a logout already performed
            // in another tab. That is not an attack — the session is already
            // gone, which is precisely what this endpoint was asked to
            // achieve — and refusing turns "log me out" into a raw protocol
            // error on a page the user can no longer act on.
            //
            // The CSRF protection this check exists for (#N2) is forcing a
            // logout on a victim who IS signed in, so the refusal is kept for
            // exactly that case and dropped for the other. Falling through
            // reaches the same sign-out path the missing-cookie case already
            // takes, which is a no-op followed by the validated
            // post_logout_redirect_uri.
            if (User?.Identity?.IsAuthenticated == true)
            {
                _logger.LogWarning(
                    "Refused an end-session POST: antiforgery validation failed while a session was active. {Reason}",
                    ex.Message);

                return BadRequest(new { error = "invalid_request", error_description = ex.Message });
            }

            _logger.LogInformation(
                "Accepted an end-session POST whose antiforgery token outlived its session; there is nothing left to sign out.");
        }

        // The Management recovery action must not immediately reuse the
        // browser's 30-day "remember this device" decision. Clear that
        // client cookie before signing out, then send the operator to the
        // login page so the next password sign-in reaches the TOTP step.
        var forceMfa = Request.HasFormContentType &&
            string.Equals(
                Request.Form["force_mfa"].ToString(),
                "true",
                StringComparison.OrdinalIgnoreCase);
        if (forceMfa)
        {
            await _signInManager.ForgetTwoFactorClientAsync();
        }

        // Capture the subject BEFORE SignOutAsync clears the cookie principal —
        // we need it to enumerate the RPs whose sessions to terminate via
        // back-channel logout (item 3.2 [L1]). The distributor is a no-op when
        // BackchannelLogout is disabled, so this call is cheap in that case.
        // ControllerBase.User is annotated nullable (it resolves
        // HttpContext?.User); during a live request it is never null, but
        // normalize once so the claim reads below satisfy the contract.
        var principal = User ?? new ClaimsPrincipal();
        var sessionId = principal.GetClaim(SessionIdClaimType);
        var user = await _userManager.GetUserAsync(principal);
        var userId = user is null
            ? principal.GetClaim(Claims.Subject)
                ?? principal.FindFirstValue(System.Security.Claims.ClaimTypes.NameIdentifier)
            : await _userManager.GetUserIdAsync(user);

        // RP-initiated logout is intentionally idempotent. The Identity cookie
        // may already be absent (expired, explicitly cleared or lost during a
        // failover) while the validated end-session request is still valid.
        // In that case there is no subject-specific fan-out to perform, but the
        // local sign-out and registered post-logout redirect must still finish.

        // Resolve the RP front-channel targets while the subject/session is
        // still available. Only a short-lived opaque context identifier is
        // carried through the OpenIddict sign-out response; RP URLs never
        // come from the browser query string.
        string? frontchannelContext = null;
        if (!string.IsNullOrEmpty(userId))
        {
            frontchannelContext = await _frontchannelLogoutDispatcher.PrepareAsync(
                userId,
                sessionId,
                HttpContext.RequestAborted);
        }

        await _signInManager.SignOutAsync();

        // Distribute the back-channel logout to RPs. Delivery is awaited with
        // a strict upper bound so scoped OpenIddict managers are never used by
        // abandoned fire-and-forget tasks after this request is disposed.
        // A slow/down RP still cannot prevent the local sign-out.
        if (!string.IsNullOrEmpty(userId))
        {
            try
            {
                using var timeout = CancellationTokenSource.CreateLinkedTokenSource(
                    HttpContext.RequestAborted);
                timeout.CancelAfter(TimeSpan.FromSeconds(8));
                await _backchannelLogoutDispatcher.DistributeAsync(
                    userId,
                    sessionId,
                    timeout.Token);
            }
            catch (Exception)
            {
                // Defense in depth: the distributor already swallows per-RP
                // errors, but never let any exception here surface — local
                // logout succeeded and that is what the user sees.
                // (No logger field on this controller; the distributor logs.)
            }

            try
            {
                using var timeout = CancellationTokenSource.CreateLinkedTokenSource(
                    HttpContext.RequestAborted);
                timeout.CancelAfter(TimeSpan.FromSeconds(8));
                await _sharedSignalsDispatcher.SessionRevokedAsync(
                    userId,
                    sessionId,
                    timeout.Token);
            }
            catch (Exception)
            {
                // Shared Signals is an asynchronous security notification. A
                // receiver outage must not undo the already-completed local
                // logout; the dispatcher logs observable delivery failures.
            }
        }

        var redirectUri = forceMfa
            ? QueryHelpers.AddQueryString(
                "/account/login",
                "returnUrl",
                "/management/")
            : frontchannelContext is null
            ? "/"
            : QueryHelpers.AddQueryString(
                "/connect/frontchannel-logout",
                "logout_context",
                frontchannelContext);

        return SignOut(
            authenticationSchemes: OpenIddictServerAspNetCoreDefaults.AuthenticationScheme,
            properties: new AuthenticationProperties { RedirectUri = redirectUri });
    }

    // -----------------------------------------------------------------------
    // /connect/frontchannel-logout — one-time OP iframe fan-out page from
    // OIDC Front-Channel Logout 1.0. This is an internal continuation target,
    // not an RP-supplied URI and not an endpoint advertised in discovery.
    // -----------------------------------------------------------------------
    [HttpGet("~/connect/frontchannel-logout")]
    [IgnoreAntiforgeryToken]
    public async Task<IActionResult> FrontchannelLogout(
        [FromQuery(Name = "logout_context")] string? contextId)
    {
        var logoutUris = contextId is null
            ? []
            : await _frontchannelLogoutDispatcher.ConsumeAsync(
                contextId,
                HttpContext.RequestAborted);

        if (logoutUris.Count == 0)
        {
            return Redirect("/");
        }

        Response.Headers.CacheControl = "no-store";
        Response.Headers.Pragma = "no-cache";

        // The global STS CSP intentionally defaults to same-origin only. This
        // narrowly-scoped page must frame the exact registered RP origins, so
        // emit a stricter page-specific policy with only those origins.
        var frameSources = logoutUris
            .Select(value => new Uri(value, UriKind.Absolute).GetLeftPart(UriPartial.Authority))
            .Distinct(StringComparer.Ordinal)
            .Order(StringComparer.Ordinal)
            .ToArray();
        Response.Headers.ContentSecurityPolicy =
            "default-src 'none'; frame-src " + string.Join(' ', frameSources) +
            "; frame-ancestors 'none'; base-uri 'none'; form-action 'none'";

        var html = new StringBuilder(
            "<!doctype html><html lang=\"pt-BR\"><head><meta charset=\"utf-8\">" +
            "<meta name=\"referrer\" content=\"no-referrer\">" +
            "<meta http-equiv=\"refresh\" content=\"3;url=/\">" +
            "<title>Encerrando sessões conectadas</title></head><body>" +
            "<h1>Encerrando sessões conectadas</h1>" +
            "<p>Você será redirecionado em instantes.</p>");

        for (var index = 0; index < logoutUris.Count; index++)
        {
            html.Append("<iframe hidden title=\"Logout da aplicação ")
                .Append(index + 1)
                .Append("\" src=\"")
                .Append(HtmlEncoder.Default.Encode(logoutUris[index]))
                .Append("\"></iframe>");
        }

        html.Append("<p><a href=\"/\">Continuar</a></p></body></html>");
        return Content(html.ToString(), "text/html; charset=utf-8");
    }
}
