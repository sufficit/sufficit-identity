using System.Security.Claims;
using Microsoft.AspNetCore; // GetOpenIddictServerRequest() extension lives here
using Microsoft.AspNetCore.Antiforgery;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.RateLimiting;
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
/// This is the exact, load-bearing contract the embedded public UI's
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
///    renamed from here. After cookie authentication, this action projects
///    the validated OpenIddict principal into an encrypted, short-lived
///    presentation ticket and redirects to the UI's `/device` page. The
///    ticket is what lets that page show the real client and requested scopes
///    without trusting client-controlled query parameters.
///
/// 2. GET /connect/device/info?user_code=XXXX-XXXX
///    Backward-compatible JSON endpoint (NOT an OpenIddict-recognized path —
///    a plain read-only lookup, anonymous, no state change):
///      200 {"valid":true}
///      200 {"valid":false}
///    Client metadata and scopes are deliberately NOT returned here: the
///    smaller human-readable code space can be probed anonymously. The UI
///    obtains those details only from the protected ticket created by action
///    1 after login. This lookup is best-effort: exceptions degrade to
///    <c>valid:false</c> rather than a 500, since it is a display
///    convenience only and never load-bearing for the actual grant.
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
///        embedded UI project).
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
///    On approved=true: SignIn with the subject plus the scopes/resources
///    restored from OpenIddict's validated pending principal. Reading scopes
///    from the verification request would silently drop them because that
///    request only carries user_code.
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
    private readonly OpenIddictDeviceAuthorizationContextService _deviceContextService;
    private readonly ScopeEntitlementProvisioner _entitlementProvisioner;

    public DeviceController(
        IOpenIddictTokenManager tokenManager,
        IOpenIddictApplicationManager applicationManager,
        SignInManager<ApplicationUser> signInManager,
        UserManager<ApplicationUser> userManager,
        IAntiforgery antiforgery,
        OpenIddictDeviceAuthorizationContextService deviceContextService,
        ScopeEntitlementProvisioner entitlementProvisioner)
    {
        _tokenManager = tokenManager;
        _applicationManager = applicationManager;
        _signInManager = signInManager;
        _userManager = userManager;
        _antiforgery = antiforgery;
        _deviceContextService = deviceContextService;
        _entitlementProvisioner = entitlementProvisioner;
    }

    // -----------------------------------------------------------------------
    // ~/connect/device (GET) — see contract item 1 above.
    // -----------------------------------------------------------------------
    [HttpGet("~/connect/device")]
    public async Task<IActionResult> Device()
    {
        var request = HttpContext.GetOpenIddictServerRequest() ??
            throw new InvalidOperationException("The OpenID Connect request cannot be retrieved.");

        if (string.IsNullOrWhiteSpace(request.UserCode))
        {
            return Redirect("/device/usercode");
        }

        // Do not disclose the client or scopes to an anonymous caller that is
        // probing the smaller human-readable user-code space. Authentication
        // happens at the real protocol endpoint so only the signed-in account
        // receives the encrypted presentation ticket.
        var session = await HttpContext.AuthenticateAsync();
        if (session is not { Succeeded: true })
        {
            return Challenge(new AuthenticationProperties
            {
                RedirectUri = Request.PathBase + Request.Path + Request.QueryString
            });
        }

        var authorization = await HttpContext.AuthenticateAsync(
            OpenIddictServerAspNetCoreDefaults.AuthenticationScheme);
        if (authorization is not { Succeeded: true, Principal: not null })
        {
            return BadRequest(new
            {
                error = Errors.InvalidRequest,
                error_description = "The pending device authorization request cannot be retrieved."
            });
        }

        var ticket = await _deviceContextService.CreateTicketAsync(
            request.UserCode,
            authorization.Principal,
            HttpContext.RequestAborted);
        if (ticket is null)
        {
            return BadRequest(new
            {
                error = Errors.InvalidRequest,
                error_description = "The device authorization request is invalid or expired."
            });
        }

        var target = QueryHelpers.AddQueryString("/device", new Dictionary<string, string?>
        {
            ["code"] = request.UserCode,
            [OpenIddictDeviceAuthorizationContextService.TicketParameterName] = ticket,
        });

        return Redirect(target);
    }

    // -----------------------------------------------------------------------
    // /connect/device/info (GET) — see contract item 2 above.
    // -----------------------------------------------------------------------
    [AllowAnonymous]
    [HttpGet("/connect/device/info")]
    [EnableRateLimiting("device-information")]
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

            // OpenIddict stores user-code entries under its private canonical
            // token-type identifier, not under the short request parameter
            // name ("user_code"). Comparing against Parameters.UserCode made
            // every freshly issued code look invalid even though the reference
            // lookup and status check above had succeeded.
            if (!await _tokenManager.HasTypeAsync(token, TokenTypeIdentifiers.Private.UserCode))
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

            // L1 fix: do NOT return clientId/clientName from this anonymous
            // endpoint. The user-code space is small enough to enumerate, and
            // revealing which client is mid-flow is a pre-attack signal. The
            // device verification page (/device) shows the client name AFTER
            // the user signs in — not before.
            return Ok(new { valid = true });
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

        // The OpenIddict authentication result is the validated pending
        // device transaction. It carries the scopes/resources originally
        // requested at /connect/deviceauthorization. The verification request
        // itself only contains user_code, so request.GetScopes() is empty here
        // and must never be used as the grant source.
        var authorization = await HttpContext.AuthenticateAsync(
            OpenIddictServerAspNetCoreDefaults.AuthenticationScheme);
        if (authorization is not { Succeeded: true, Principal: not null })
        {
            return BadRequest(new
            {
                error = Errors.InvalidRequest,
                error_description = "The pending device authorization request cannot be retrieved."
            });
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
                })
                {
                    RedirectUri = "/device?result=denied"
                });
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

        var approvedScopes = authorization.Principal.GetScopes();
        var entitlementResult = await _entitlementProvisioner.ProvisionAsync(
            user,
            approvedScopes,
            HttpContext.RequestAborted);
        if (!entitlementResult.Succeeded)
        {
            return StatusCode(
                StatusCodes.Status503ServiceUnavailable,
                new
                {
                    error = "temporarily_unavailable",
                    error_description =
                        "The approved application access could not be prepared. Please try again."
                });
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
        identity.SetScopes(approvedScopes);
        identity.SetResources(authorization.Principal.GetResources());

        return SignIn(
            new ClaimsPrincipal(identity),
            new AuthenticationProperties
            {
                RedirectUri = "/device?result=approved"
            },
            OpenIddictServerAspNetCoreDefaults.AuthenticationScheme);
    }

    private static string NormalizeUserCode(string code) =>
        code.Trim().ToUpperInvariant().Replace("-", string.Empty).Replace(" ", string.Empty);
}
