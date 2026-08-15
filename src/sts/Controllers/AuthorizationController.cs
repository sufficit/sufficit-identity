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

/// <summary>
/// Implements the OAuth/OIDC <c>/connect/*</c> endpoints.
///
/// This is an API-only STS: there is no built-in login UI. For interactive
/// flows (authorization_code), the controller challenges to the login path
/// configured in the application cookie (default <c>/login</c>) — which a
/// separate frontend repository should serve. With <c>prompt=none</c>, the
/// STS returns <c>login_required</c>/<c>interaction_required</c> instead.
/// </summary>
public class AuthorizationController : Controller
{
    private const string SessionIdClaimType =
        OidcSessionClaimsPrincipalFactory.SessionIdClaimType;

    private readonly IOpenIddictApplicationManager _applicationManager;
    private readonly IOpenIddictAuthorizationManager _authorizationManager;
    private readonly IOpenIddictScopeManager _scopeManager;
    private readonly IUserAvatarUrlResolver _avatarUrlResolver;
    private readonly SignInManager<ApplicationUser> _signInManager;
    private readonly UserManager<ApplicationUser> _userManager;
    private readonly Grants.TokenGrantDispatcher _grantDispatcher;
    private readonly Grants.GrantOperations _grants;
    private readonly IApplicationClaimDestinationPolicy _applicationClaimPolicy;
    private readonly Logout.IBackchannelLogoutDispatcher _backchannelLogoutDispatcher;
    private readonly Logout.IFrontchannelLogoutDispatcher _frontchannelLogoutDispatcher;
    private readonly SharedSignals.ISharedSignalsDispatcher _sharedSignalsDispatcher;
    private readonly Fapi2Options _fapi2Options;
    private readonly IAntiforgery _antiforgery;
    private readonly ILogger<AuthorizationController> _logger;

    public AuthorizationController(
        IOpenIddictApplicationManager applicationManager,
        IOpenIddictAuthorizationManager authorizationManager,
        IOpenIddictScopeManager scopeManager,
        IUserAvatarUrlResolver avatarUrlResolver,
        SignInManager<ApplicationUser> signInManager,
        UserManager<ApplicationUser> userManager,
        IConfiguration configuration,
        IAntiforgery antiforgery,
        IApplicationClaimDestinationPolicy applicationClaimPolicy,
        Logout.IBackchannelLogoutDispatcher backchannelLogoutDispatcher,
        Logout.IFrontchannelLogoutDispatcher frontchannelLogoutDispatcher,
        SharedSignals.ISharedSignalsDispatcher sharedSignalsDispatcher,
        Grants.TokenGrantDispatcher grantDispatcher,
        Grants.GrantOperations grants,
        ILogger<AuthorizationController> logger)
    {
        _applicationManager = applicationManager;
        _authorizationManager = authorizationManager;
        _scopeManager = scopeManager;
        _avatarUrlResolver = avatarUrlResolver;
        _signInManager = signInManager;
        _userManager = userManager;
        _grantDispatcher = grantDispatcher;
        _grants = grants;
        _applicationClaimPolicy = applicationClaimPolicy;
        _antiforgery = antiforgery;
        _backchannelLogoutDispatcher = backchannelLogoutDispatcher;
        _frontchannelLogoutDispatcher = frontchannelLogoutDispatcher;
        _sharedSignalsDispatcher = sharedSignalsDispatcher;
        _logger = logger;
        // FAPI options drive the authorize-endpoint dpop_jkt binding; the
        // token-endpoint DPoP/FAPI preamble lives in the grant dispatcher.
        _fapi2Options = (configuration.GetSection("Sufficit:Identity")
            .Get<SufficitIdentityOptions>() ?? new SufficitIdentityOptions()).Fapi2;
    }

    // -----------------------------------------------------------------------
    // /connect/authorize
    // -----------------------------------------------------------------------
    [HttpGet("~/connect/authorize")]
    [HttpPost("~/connect/authorize")]
    public async Task<IActionResult> Authorize()
    {
        var request = HttpContext.GetOpenIddictServerRequest() ??
            throw new InvalidOperationException("The OpenID Connect request cannot be retrieved.");

        var result = await HttpContext.AuthenticateAsync();

        // Not authenticated → challenge. With prompt=none return login_required.
        if (result is not { Succeeded: true })
        {
            if (request.HasPromptValue(PromptValues.None))
            {
                return Forbid(
                    authenticationSchemes: OpenIddictServerAspNetCoreDefaults.AuthenticationScheme,
                    properties: new AuthenticationProperties(new Dictionary<string, string?>
                    {
                        [OpenIddictServerAspNetCoreConstants.Properties.Error] = Errors.LoginRequired,
                        [OpenIddictServerAspNetCoreConstants.Properties.ErrorDescription] =
                            "The user is not logged in."
                    }));
            }

            return Challenge(new AuthenticationProperties
            {
                RedirectUri = Request.PathBase + Request.Path +
                    QueryString.Create(Request.HasFormContentType ? Request.Form : Request.Query)
            });
        }

        var user = await _userManager.GetUserAsync(result.Principal) ??
            throw new InvalidOperationException("The user details cannot be retrieved.");

        var application = await _applicationManager.FindByClientIdAsync(request.ClientId!) ??
            throw new InvalidOperationException(
                "Details concerning the calling client application cannot be found.");

        var requestedScopes = await GetRequestedScopesAsync(request, application);
        var authorizations = await Grants.GrantOperations.ToListAsync(_authorizationManager.FindAsync(
            subject: await _userManager.GetUserIdAsync(user),
            client: await _applicationManager.GetIdAsync(application),
            status: Statuses.Valid,
            type: AuthorizationTypes.Permanent,
            scopes: requestedScopes));

        var consentType = await _applicationManager.GetConsentTypeAsync(application);
        var forcesReconsent = request.HasPromptValue(PromptValues.Consent);
        var consentRequirement = AuthorizationConsentPolicy.Evaluate(
            consentType,
            authorizations.Count > 0,
            forcesReconsent);

        // External consent: only allow if an explicit authorization already exists.
        if (consentRequirement == AuthorizationConsentRequirement.ExistingAuthorization)
        {
            return Forbid(
                authenticationSchemes: OpenIddictServerAspNetCoreDefaults.AuthenticationScheme,
                properties: new AuthenticationProperties(new Dictionary<string, string?>
                {
                    [OpenIddictServerAspNetCoreConstants.Properties.Error] = Errors.ConsentRequired,
                    [OpenIddictServerAspNetCoreConstants.Properties.ErrorDescription] =
                        "The logged in user is not allowed to access this client application."
                }));
        }

        // ---------------------------------------------------------------------
        // Interactive consent (#B3, P0 #4) + CSRF hardening (#N1).
        //
        // CONTRACT with the embedded public UI:
        //  - When interactive consent is required (see the switch below), this
        //    action 302-redirects the browser to `/consent?{original query
        //    string, verbatim}` — every parameter THIS request itself received
        //    (client_id, redirect_uri, response_type, scope, state, nonce,
        //    code_challenge, code_challenge_method, prompt, resource, etc.) is
        //    forwarded as-is. The UI must read client_id/scope directly off ITS
        //    OWN query string — NOT via HttpContext.GetOpenIddictServerRequest(),
        //    which is only populated on the actual /connect/authorize request;
        //    `/consent` is not a registered OpenIddict endpoint URI.
        //  - The UI's /consent page renders a form and POSTs the decision back
        //    to THIS SAME endpoint (`/connect/authorize`, POST — already
        //    accepted above) with:
        //      * every original parameter re-included as hidden fields, except
        //        `scope` MAY be narrowed to just the scopes the user checked
        //        (space-separated) for per-scope granularity — OpenIddict's own
        //        scope validation still runs on the resubmitted request, so an
        //        upward-tampered scope list is rejected the same way any other
        //        /connect/authorize request would be;
        //      * a `consent_decision` field set to exactly "allow" or "deny";
        //      * an antiforgery token (Blazor `<AntiforgeryToken />` component
        //        OR a hidden `__RequestVerificationToken` input). This is
        //        REQUIRED: without it, a malicious third-party page could POST
        //        `consent_decision=allow` to this endpoint riding the victim's
        //        Identity cookie (SameSite=Lax does not block top-level form
        //        POST navigations across all browsers/legacy cases) and grant
        //        a client the victim never approved (#N1). The token is
        //        validated server-side here via IAntiforgery.ValidateRequestAsync
        //        — the STS host is API-only and does NOT register the MVC
        //        [ValidateAntiForgeryToken] auto-filter, so the Blazor
        //        EditForm/AntiforgeryToken component alone is NOT sufficient.
        //  - "deny" → this action returns `access_denied` to the client (via
        //    Forbid), closing the transaction. "allow" → the request is granted
        //    using request.GetScopes() (i.e. whatever the resubmitted `scope`
        //    field contains).
        // ---------------------------------------------------------------------
        if (Request.HasFormContentType && Request.Form.ContainsKey("consent_decision"))
        {
            // CSRF (#N1): mirror DeviceController.Verify's pattern — validate
            // the antiforgery token BEFORE reading the decision. A bad/missing
            // token returns 400 invalid_request instead of granting/denying.
            try
            {
                await _antiforgery.ValidateRequestAsync(HttpContext);
            }
            catch (AntiforgeryValidationException ex)
            {
                return BadRequest(new { error = "invalid_request", error_description = ex.Message });
            }

            var decision = Request.Form["consent_decision"].ToString();

            if (string.Equals(decision, "allow", StringComparison.OrdinalIgnoreCase))
            {
                _logger.LogInformation(
                    "OAuth consent approved. ClientId={ClientId}; ScopeCount={ScopeCount}; "
                    + "TraceId={TraceId}.",
                    request.ClientId,
                    requestedScopes.Length,
                    HttpContext.TraceIdentifier);
                // Fall through to the grant below — no further consent check.
            }
            else
            {
                // "deny", or anything else: fail closed. RFC 6749 §4.1.2.1.
                return Forbid(
                    authenticationSchemes: OpenIddictServerAspNetCoreDefaults.AuthenticationScheme,
                    properties: new AuthenticationProperties(new Dictionary<string, string?>
                    {
                        [OpenIddictServerAspNetCoreConstants.Properties.Error] = Errors.AccessDenied,
                        [OpenIddictServerAspNetCoreConstants.Properties.ErrorDescription] =
                            "The resource owner denied the authorization request."
                    }));
            }
        }
        else
        {
            if (Request.HasFormContentType
                && Request.Form.ContainsKey("__RequestVerificationToken"))
            {
                _logger.LogWarning(
                    "OAuth consent POST arrived without consent_decision. "
                    + "ClientId={ClientId}; ScopeCount={ScopeCount}; TraceId={TraceId}.",
                    request.ClientId,
                    requestedScopes.Length,
                    HttpContext.TraceIdentifier);
            }

            // No decision attached to this request: apply the OpenIddict
            // consent-type policy (mirrors the canonical AuthorizationController
            // pattern from the OpenIddict samples — ConsentTypes.Implicit never
            // asks; Explicit asks unless a valid cached authorization already
            // covers the request AND the client isn't forcing re-consent via
            // prompt=consent; Systematic always asks).
            //
            // Previously, `!request.HasPromptValue(PromptValues.Consent)` was
            // used to SKIP this whole block (i.e. prompt=consent bypassed the
            // check entirely and fell straight through to auto-grant below) —
            // that inversion is the #B3 bug: a client explicitly asking to
            // reconfirm consent got NO interaction at all. Fixed by making
            // prompt=consent participate in the centralized policy instead of
            // bypassing the consent decision.
            if (consentRequirement == AuthorizationConsentRequirement.Interactive)
            {
                if (request.HasPromptValue(PromptValues.None))
                {
                    return Forbid(
                        authenticationSchemes: OpenIddictServerAspNetCoreDefaults.AuthenticationScheme,
                        properties: new AuthenticationProperties(new Dictionary<string, string?>
                        {
                            [OpenIddictServerAspNetCoreConstants.Properties.Error] = Errors.ConsentRequired,
                            [OpenIddictServerAspNetCoreConstants.Properties.ErrorDescription] =
                                "Interactive user consent is required."
                        }));
                }

                var forwardedQuery = QueryString.Create(Request.HasFormContentType ? Request.Form : Request.Query);
                return Redirect("/consent" + forwardedQuery);
            }
        }

        var identity = await _grants.BuildIdentityAsync(user, result.Principal, User);
        identity.SetScopes(requestedScopes);
        identity.SetResources(await _grants.ResolveResourcesAsync(identity, request));

        // FAPI 2.0 + DPoP authorization-code binding (RFC 9449 §10.1):
        // dpop_jkt was authenticated inside PAR by the client and restored by
        // OpenIddict. Preserve it in the authorization-code principal so the
        // token endpoint can require a proof made with the same key.
        if (Fapi.Fapi2Policy.Applies(_fapi2Options, request.ClientId) &&
            _fapi2Options.SenderConstraint == Fapi2SenderConstraint.Dpop)
        {
            identity.SetClaim(
                Dpop.DpopProofValidator.BindingThumbprintClaimType,
                (string?)request["dpop_jkt"]);
        }

        var authorization = authorizations.LastOrDefault() ?? await _authorizationManager.CreateAsync(
            identity: identity,
            subject: await _userManager.GetUserIdAsync(user),
            client: (await _applicationManager.GetIdAsync(application))!,
            type: AuthorizationTypes.Permanent,
            scopes: identity.GetScopes());

        identity.SetAuthorizationId(await _authorizationManager.GetIdAsync(authorization));
        identity.SetDestinations(_grants.GetDestinations);

        return SignIn(new ClaimsPrincipal(identity), OpenIddictServerAspNetCoreDefaults.AuthenticationScheme);
    }

    // -----------------------------------------------------------------------
    // /connect/token
    // -----------------------------------------------------------------------
    [HttpPost("~/connect/token")]
    [IgnoreAntiforgeryToken]
    [Produces("application/json")]
    public async Task<IActionResult> Exchange()
    {
        var request = HttpContext.GetOpenIddictServerRequest() ??
            throw new InvalidOperationException("The OpenID Connect request cannot be retrieved.");

        // A2 (eval 2026-08-14): every grant branch and the cross-cutting DPoP
        // preamble moved to Grants/ — TokenGrantDispatcher validates the DPoP
        // proof once (nonce dance included) and hands the request to the
        // registered ITokenGrantHandler for its grant type.
        return await _grantDispatcher.DispatchAsync(HttpContext, request);
    }

    // -----------------------------------------------------------------------
    // /connect/userinfo
    // -----------------------------------------------------------------------
    [Authorize(AuthenticationSchemes = OpenIddictServerAspNetCoreDefaults.AuthenticationScheme)]
    [HttpGet("~/connect/userinfo")]
    [HttpPost("~/connect/userinfo")]
    public async Task<IActionResult> Userinfo()
    {
        // NOT _userManager.GetUserAsync(User): that overload resolves the
        // subject via ClaimTypes.NameIdentifier (ASP.NET Core Identity's
        // IdentityOptions.ClaimsIdentity.UserIdClaimType default), but every
        // access token issued by this controller carries the subject under
        // Claims.Subject ("sub") instead — OpenIddict's validation handler
        // does not remap claim types the way the legacy JwtBearer handler's
        // DefaultInboundClaimTypeMap does. GetUserAsync(User) therefore
        // always returned null here (this bug was previously undetected:
        // no test exercised /connect/userinfo — see AuthorizationCodeFlowTests).
        // Same subject-lookup pattern already used by ExchangeForUserAsync/
        // ExchangeForTokenExchangeAsync above.
        var subject = User.GetClaim(Claims.Subject);
        var user = (subject is not null ? await _userManager.FindByIdAsync(subject) : null) ??
            throw new InvalidOperationException("The user details cannot be retrieved.");

        var userId = await _userManager.GetUserIdAsync(user);
        var persistedClaims = await _userManager.GetClaimsAsync(user);
        var displayName = persistedClaims
            .LastOrDefault(claim => string.Equals(
                claim.Type,
                Claims.Name,
                StringComparison.Ordinal))
            ?.Value;

        var claims = new Dictionary<string, object?>
        {
            [Claims.Subject] = userId
        };

        if (User.HasScope(Scopes.Email))
        {
            claims[Claims.Email] = await _userManager.GetEmailAsync(user);
            claims[Claims.EmailVerified] = await _userManager.IsEmailConfirmedAsync(user);
        }

        if (User.HasScope(Scopes.Profile))
        {
            claims[Claims.Name] = displayName ?? await _userManager.GetUserNameAsync(user);
            claims[Claims.PreferredUsername] = await _userManager.GetUserNameAsync(user);

            var avatarUrl = await _avatarUrlResolver.ResolveAsync(
                userId,
                HttpContext.RequestAborted);
            if (!string.IsNullOrWhiteSpace(avatarUrl))
            {
                claims[Claims.Picture] = avatarUrl;
            }
        }

        if (User.HasScope(Scopes.Roles))
        {
            claims[Claims.Role] = await _userManager.GetRolesAsync(user);
        }

        // UserInfo is the generic extension point for application claims.
        // Only claims explicitly mapped by the composing host and requested
        // through their corresponding scope are returned; the STS never
        // interprets their names or values.
        if (_applicationClaimPolicy.MappedClaimScopes.Count > 0)
        {
            foreach (var mapping in _applicationClaimPolicy.MappedClaimScopes)
            {
                if (!User.HasScope(mapping.Value))
                {
                    continue;
                }

                var values = persistedClaims
                    .Where(claim => string.Equals(claim.Type, mapping.Key, StringComparison.Ordinal))
                    .Select(claim => claim.Value)
                    .Distinct(StringComparer.Ordinal)
                    .ToArray();
                if (values.Length == 1)
                {
                    claims[mapping.Key] = values[0];
                }
                else if (values.Length > 1)
                {
                    claims[mapping.Key] = values;
                }
            }
        }

        return Ok(claims);
    }

    private async Task<ImmutableArray<string>> GetRequestedScopesAsync(
        OpenIddictRequest request,
        object application)
    {
        var scopes = request.GetScopes().ToHashSet(StringComparer.Ordinal);

        // The consent UI submits one checked `scope` field per selected item.
        // OpenIddict validates that multi-value field but GetScopes() only
        // projects the scalar representation, which previously discarded all
        // granted scopes on the consent POST. Losing `offline_access` prevented
        // refresh-token issuance; losing `profile`/`email` also reduced
        // /connect/userinfo to `sub` only.
        if (Request.HasFormContentType && Request.Form.ContainsKey(Parameters.Scope))
        {
            foreach (var value in Request.Form[Parameters.Scope])
            {
                foreach (var scope in value?.Split(
                    ' ',
                    StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries) ?? [])
                {
                    scopes.Add(scope);
                }
            }
        }

        var allowedScopes = ImmutableArray.CreateBuilder<string>();
        foreach (var scope in scopes)
        {
            if (await _applicationManager.HasPermissionAsync(
                application,
                Permissions.Prefixes.Scope + scope))
            {
                allowedScopes.Add(scope);
            }
        }

        return allowedScopes.ToImmutable();
    }

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
            return BadRequest(new { error = "invalid_request", error_description = ex.Message });
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
        var sessionId = User.GetClaim(SessionIdClaimType);
        var user = await _userManager.GetUserAsync(User);
        var userId = user is null
            ? User.GetClaim(Claims.Subject)
                ?? User.FindFirstValue(System.Security.Claims.ClaimTypes.NameIdentifier)
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
