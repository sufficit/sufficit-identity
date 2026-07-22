using System.Security.Claims;
using Microsoft.AspNetCore; // GetOpenIddictServerRequest() extension lives here
using Microsoft.AspNetCore.Antiforgery;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.WebUtilities;
using Microsoft.IdentityModel.Tokens;
using OpenIddict.Abstractions;
using OpenIddict.Server.AspNetCore;
using Sufficit.Identity.Core.Entities;
using static OpenIddict.Abstractions.OpenIddictConstants;

namespace Sufficit.Identity.STS.Controllers;

/// <summary>
/// Device Authorization Grant (RFC 8628) — end-user verification endpoints
/// (#B1, P0 #3). The token-endpoint half of this flow
/// (<c>grant_type=device_code</c>) lives in
/// <see cref="AuthorizationController.ExchangeForDeviceCodeAsync"/>; this
/// controller is the browser-facing half the user completes on whatever
/// device they used to read the polling client's displayed code.
///
/// ================================ CONTRACT =================================
/// This is the exact, load-bearing contract the sufficit-identity-ui repo's
/// device page must follow. The paths below are NOT an arbitrary REST
/// convention — they are constrained by how OpenIddict's ASP.NET Core
/// integration binds a signed-in principal to a pending device_code.
///
/// 1. GET ~/connect/device[?user_code=XXXX-XXXX]
///    The RFC 8628 verification_uri / verification_uri_complete OpenIddict
///    itself hands to the polling client/device. This is the ONE URI
///    configured server-side via SetEndUserVerificationEndpointUris
///    (src/sts/ServiceCollectionExtensions.cs, out of this file's
///    ownership) with EnableEndUserVerificationEndpointPassthrough() already
///    on — it is not a path this controller invented, and it cannot be
///    renamed from here. This action does nothing but redirect the browser
///    to the UI's human-facing page at `/device` (forwarding the code as
///    `?code=XXXX-XXXX` when one was present), purely for display.
///
/// 2. GET /connect/device/info?user_code=XXXX-XXXX
///    Ordinary JSON endpoint (NOT an OpenIddict-recognized path — a plain
///    read-only lookup, anonymous, no state change) the UI calls to render
///    "what's being authorized" before showing the approve/deny buttons:
///      200 {"valid":true,"clientId":"...","clientName":"..."}
///      200 {"valid":false}
///    NOTE: scopes are deliberately NOT included. OpenIddict does not expose
///    a persisted token's decrypted principal/scopes through the public
///    IOpenIddictTokenManager API — only Payload (an opaque encrypted
///    string) is stored; OpenIddictTokenDescriptor.Principal is explicitly
///    documented as "not stored by the default token stores". Surfacing
///    scopes here would need a custom OpenIddict event handler stashing them
///    as token Properties at /connect/deviceauthorization time — that lives
///    in src/sts/ServiceCollectionExtensions.cs, out of this file's
///    scope. Flagged as follow-up, not implemented here. This lookup is
///    also best-effort: any unexpected exception degrades to
///    <c>valid:false</c> rather than a 500, since it is a display
///    convenience only — never load-bearing for the actual grant (that
///    happens entirely through action 3 below plus OpenIddict's own request
///    validation).
///
/// 3. POST ~/connect/device
///    THE SAME real OpenIddict endpoint as (1) — deliberately NOT a
///    `/connect/device/verify` sub-path, even though that would read more
///    RESTfully. SignIn(OpenIddictServerAspNetCoreDefaults.AuthenticationScheme,
///    ...) only binds a principal to the pending device_code when invoked
///    from within a request OpenIddict itself recognizes as the
///    end-user-verification endpoint (the enabled passthrough is scoped to
///    the exact configured URI). Posting the decision anywhere else cannot
///    complete the device flow — there is no supported way to attach a
///    principal to a device_code from outside that endpoint.
///
///    Required form fields:
///      - user_code : the code the user entered/confirmed, in whatever
///                    format the user typed it — OpenIddict itself
///                    normalizes/validates it before this action runs; an
///                    invalid/expired/unknown code never reaches this action
///                    body at all (OpenIddict responds directly).
///      - approved  : "true" or "false" (string).
///      - an antiforgery field (e.g. an &lt;AntiforgeryToken /&gt; Blazor
///        component, or a hidden __RequestVerificationToken input) —
///        validated explicitly below via IAntiforgery.ValidateRequestAsync,
///        independent of the [ValidateAntiForgeryToken] MVC filter (see
///        AuthorizationController.LogoutPost's comment for why this
///        codebase doesn't lean on that filter for forms rendered from the
///        sibling UI project).
///      - the user must already be authenticated via the same cookie
///        /connect/authorize and the UI's Blazor pages use; if not, this
///        action challenges to the login page with a return URL back to
///        this same form. The UI should also check this before rendering
///        the form (defense in depth, not the only check).
///
///    IMPORTANT: the UI's form must be REAL, static server-rendered HTML — a
///    plain &lt;form method="post"&gt; full-page submit, NOT an interactive
///    Blazor EditForm/OnValidSubmit bound over a SignalR circuit. SignIn
///    requires a genuine HTTP response on the actual request that hit this
///    controller action; a Blazor interactive event handler never gets one.
///
///    On approved=true: SignIn (OpenIddict's own response for this
///    endpoint) — have the UI redirect the browser afterwards to a static
///    "device authorized, you can close this tab" page.
///    On approved=false: Forbid(access_denied) — OpenIddict's own
///    RejectDeviceCodeEntry/RejectUserCodeEntry handlers mark the
///    corresponding device_code token Rejected as a result, so the polling
///    device's NEXT /connect/token attempt gets access_denied too, not just
///    this browser response.
/// =============================================================================
/// </summary>
public class DeviceController : Controller
{
    private readonly IOpenIddictTokenManager _tokenManager;
    private readonly IOpenIddictApplicationManager _applicationManager;
    private readonly SignInManager<ApplicationUser> _signInManager;
    private readonly UserManager<ApplicationUser> _userManager;
    private readonly IAntiforgery _antiforgery;

    public DeviceController(
        IOpenIddictTokenManager tokenManager,
        IOpenIddictApplicationManager applicationManager,
        SignInManager<ApplicationUser> signInManager,
        UserManager<ApplicationUser> userManager,
        IAntiforgery antiforgery)
    {
        _tokenManager = tokenManager;
        _applicationManager = applicationManager;
        _signInManager = signInManager;
        _userManager = userManager;
        _antiforgery = antiforgery;
    }

    // -----------------------------------------------------------------------
    // ~/connect/device (GET) — see contract item 1 above.
    // -----------------------------------------------------------------------
    [HttpGet("~/connect/device")]
    public IActionResult Device()
    {
        var request = HttpContext.GetOpenIddictServerRequest() ??
            throw new InvalidOperationException("The OpenID Connect request cannot be retrieved.");

        var target = string.IsNullOrEmpty(request.UserCode)
            ? "/device"
            : QueryHelpers.AddQueryString("/device", "code", request.UserCode);

        return Redirect(target);
    }

    // -----------------------------------------------------------------------
    // /connect/device/info (GET) — see contract item 2 above.
    // -----------------------------------------------------------------------
    [AllowAnonymous]
    [HttpGet("/connect/device/info")]
    public async Task<IActionResult> Info([FromQuery(Name = "user_code")] string? userCode)
    {
        if (string.IsNullOrWhiteSpace(userCode))
        {
            return Ok(new { valid = false });
        }

        try
        {
            var normalized = NormalizeUserCode(userCode);
            var token = await _tokenManager.FindByReferenceIdAsync(normalized);
            if (token is null || !await _tokenManager.HasStatusAsync(token, Statuses.Valid))
            {
                return Ok(new { valid = false });
            }

            // Defense-in-depth type check: OpenIddict.Abstractions'
            // TokenTypeHints only publicly exposes AccessToken/RefreshToken
            // (verified against 7.6.0) — there is no public constant for the
            // device-flow user_code token type. Parameters.UserCode ("user_code")
            // is reused here on the assumption OpenIddict tags the token
            // entity's Type with the same string as the request parameter; if
            // that assumption is ever wrong for some token layout, this just
            // makes the lookup slightly more likely to fall through to
            // `valid:false` below — never a correctness/security issue for the
            // actual grant, which does not depend on this endpoint at all.
            if (!await _tokenManager.HasTypeAsync(token, Parameters.UserCode))
            {
                return Ok(new { valid = false });
            }

            var applicationId = await _tokenManager.GetApplicationIdAsync(token);
            var application = applicationId is not null
                ? await _applicationManager.FindByIdAsync(applicationId)
                : null;

            if (application is null)
            {
                return Ok(new { valid = false });
            }

            var clientId = await _applicationManager.GetClientIdAsync(application);
            var clientName = (string?)await _applicationManager.GetDisplayNameAsync(application) ?? clientId;

            return Ok(new { valid = true, clientId, clientName });
        }
        catch
        {
            // Best-effort display lookup only — never let an unexpected shape
            // (e.g. an internal token-store detail this comment's assumptions
            // got wrong) surface as a 500. See the class-level contract note.
            return Ok(new { valid = false });
        }
    }

    // -----------------------------------------------------------------------
    // ~/connect/device (POST) — see contract item 3 above.
    // -----------------------------------------------------------------------
    [HttpPost("~/connect/device")]
    public async Task<IActionResult> Verify()
    {
        var request = HttpContext.GetOpenIddictServerRequest() ??
            throw new InvalidOperationException("The OpenID Connect request cannot be retrieved.");

        try
        {
            await _antiforgery.ValidateRequestAsync(HttpContext);
        }
        catch (AntiforgeryValidationException ex)
        {
            return BadRequest(new { error = "invalid_request", error_description = ex.Message });
        }

        var result = await HttpContext.AuthenticateAsync();
        if (result is not { Succeeded: true })
        {
            return Challenge(new AuthenticationProperties
            {
                RedirectUri = Request.PathBase + Request.Path + QueryString.Create(Request.Form)
            });
        }

        var approved = string.Equals(
            Request.Form["approved"].ToString(), "true", StringComparison.OrdinalIgnoreCase);

        if (!approved)
        {
            return Forbid(
                authenticationSchemes: OpenIddictServerAspNetCoreDefaults.AuthenticationScheme,
                properties: new AuthenticationProperties(new Dictionary<string, string?>
                {
                    [OpenIddictServerAspNetCoreConstants.Properties.Error] = Errors.AccessDenied,
                    [OpenIddictServerAspNetCoreConstants.Properties.ErrorDescription] =
                        "The end user refused to authorize the device."
                }));
        }

        var user = await _userManager.GetUserAsync(result.Principal) ??
            throw new InvalidOperationException("The user details cannot be retrieved.");

        if (!await _signInManager.CanSignInAsync(user))
        {
            return Forbid(
                authenticationSchemes: OpenIddictServerAspNetCoreDefaults.AuthenticationScheme,
                properties: new AuthenticationProperties(new Dictionary<string, string?>
                {
                    [OpenIddictServerAspNetCoreConstants.Properties.Error] = Errors.InvalidGrant,
                    [OpenIddictServerAspNetCoreConstants.Properties.ErrorDescription] =
                        "The user is not allowed to sign in."
                }));
        }

        // Deliberately minimal: only Subject + Scopes need to survive onto the
        // device_code's attached principal. AuthorizationController.
        // ExchangeForDeviceCodeAsync re-derives the FULL identity
        // (name/email/roles/persisted claims) fresh from current user state
        // at token-redemption time — same rationale as the authorization_code
        // / refresh_token paths' "re-sync persisted claims" comment — so
        // there is no need (and no security benefit) to stage those claims
        // here too.
        var identity = new ClaimsIdentity(
            authenticationType: TokenValidationParameters.DefaultAuthenticationType,
            nameType: Claims.Name,
            roleType: Claims.Role);

        identity.SetClaim(Claims.Subject, await _userManager.GetUserIdAsync(user));
        identity.SetScopes(request.GetScopes());

        return SignIn(new ClaimsPrincipal(identity), OpenIddictServerAspNetCoreDefaults.AuthenticationScheme);
    }

    private static string NormalizeUserCode(string code) =>
        code.Trim().ToUpperInvariant().Replace("-", string.Empty).Replace(" ", string.Empty);
}
