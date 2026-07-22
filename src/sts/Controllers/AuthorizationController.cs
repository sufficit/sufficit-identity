using System.Security.Claims;
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
using Microsoft.IdentityModel.Tokens;
using OpenIddict.Abstractions;
using OpenIddict.Server.AspNetCore;
using Sufficit.Identity.Core.Entities;
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
    private readonly IOpenIddictApplicationManager _applicationManager;
    private readonly IOpenIddictAuthorizationManager _authorizationManager;
    private readonly IOpenIddictScopeManager _scopeManager;
    private readonly SignInManager<ApplicationUser> _signInManager;
    private readonly UserManager<ApplicationUser> _userManager;
    private readonly TokenExchangeOptions _tokenExchangeOptions;
    private readonly IAntiforgery _antiforgery;

    public AuthorizationController(
        IOpenIddictApplicationManager applicationManager,
        IOpenIddictAuthorizationManager authorizationManager,
        IOpenIddictScopeManager scopeManager,
        SignInManager<ApplicationUser> signInManager,
        UserManager<ApplicationUser> userManager,
        IConfiguration configuration,
        IAntiforgery antiforgery)
    {
        _applicationManager = applicationManager;
        _authorizationManager = authorizationManager;
        _scopeManager = scopeManager;
        _signInManager = signInManager;
        _userManager = userManager;
        _tokenExchangeOptions = configuration.GetSection("Sufficit:Identity:TokenExchange").Get<TokenExchangeOptions>()
            ?? new TokenExchangeOptions();
        _antiforgery = antiforgery;
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

        var authorizations = await ToListAsync(_authorizationManager.FindAsync(
            subject: await _userManager.GetUserIdAsync(user),
            client: await _applicationManager.GetIdAsync(application),
            status: Statuses.Valid,
            type: AuthorizationTypes.Permanent,
            scopes: request.GetScopes()));

        var consentType = await _applicationManager.GetConsentTypeAsync(application);

        // External consent: only allow if an explicit authorization already exists.
        if (consentType == ConsentTypes.External && authorizations.Count == 0)
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
        // CONTRACT with the UI (sufficit-identity-ui repo):
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
            // prompt=consent force `needsInteractiveConsent = true` instead.
            var forcesReconsent = request.HasPromptValue(PromptValues.Consent);

            var needsInteractiveConsent = consentType switch
            {
                ConsentTypes.Implicit => false,
                ConsentTypes.Explicit => authorizations.Count == 0 || forcesReconsent,
                ConsentTypes.Systematic => true,
                _ => false, // External already handled above.
            };

            if (needsInteractiveConsent)
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

        var identity = await BuildIdentityAsync(user);
        identity.SetScopes(request.GetScopes());
        identity.SetResources(await ToListAsync(_scopeManager.ListResourcesAsync(identity.GetScopes())));

        var authorization = authorizations.LastOrDefault() ?? await _authorizationManager.CreateAsync(
            identity: identity,
            subject: await _userManager.GetUserIdAsync(user),
            client: (await _applicationManager.GetIdAsync(application))!,
            type: AuthorizationTypes.Permanent,
            scopes: identity.GetScopes());

        identity.SetAuthorizationId(await _authorizationManager.GetIdAsync(authorization));
        identity.SetDestinations(GetDestinations);

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

        if (request.IsAuthorizationCodeGrantType() || request.IsRefreshTokenGrantType())
        {
            return await ExchangeForUserAsync(request);
        }

        if (request.IsDeviceCodeGrantType())
        {
            return await ExchangeForDeviceCodeAsync(request);
        }

        if (request.IsClientCredentialsGrantType())
        {
            return await ExchangeForClientAsync(request);
        }

        if (request.IsPasswordGrantType())
        {
            return await ExchangeForPasswordAsync(request);
        }

        if (request.IsTokenExchangeGrantType())
        {
            return await ExchangeForTokenExchangeAsync(request);
        }

        return Forbid(
            authenticationSchemes: OpenIddictServerAspNetCoreDefaults.AuthenticationScheme,
            properties: new AuthenticationProperties(new Dictionary<string, string?>
            {
                [OpenIddictServerAspNetCoreConstants.Properties.Error] = Errors.UnsupportedGrantType
            }));
    }

    private async Task<IActionResult> ExchangeForUserAsync(OpenIddictRequest request)
    {
        var result = await HttpContext.AuthenticateAsync(OpenIddictServerAspNetCoreDefaults.AuthenticationScheme);
        var user = await _userManager.FindByIdAsync(result.Principal!.GetClaim(Claims.Subject)!);

        if (user is null || !await _signInManager.CanSignInAsync(user))
        {
            return Forbid(
                authenticationSchemes: OpenIddictServerAspNetCoreDefaults.AuthenticationScheme,
                properties: new AuthenticationProperties(new Dictionary<string, string?>
                {
                    [OpenIddictServerAspNetCoreConstants.Properties.Error] = Errors.InvalidGrant,
                    [OpenIddictServerAspNetCoreConstants.Properties.ErrorDescription] =
                        "The token is no longer valid or the user is no longer allowed to sign in."
                }));
        }

        var identity = new ClaimsIdentity(result.Principal!.Claims,
            authenticationType: TokenValidationParameters.DefaultAuthenticationType,
            nameType: Claims.Name,
            roleType: Claims.Role);

        identity.SetClaim(Claims.Subject, await _userManager.GetUserIdAsync(user))
                .SetClaim(Claims.Email, await _userManager.GetEmailAsync(user))
                .SetClaim(Claims.Name, await _userManager.GetUserNameAsync(user))
                .SetClaim(Claims.PreferredUsername, await _userManager.GetUserNameAsync(user))
                .SetClaims(Claims.Role, [.. await _userManager.GetRolesAsync(user)]);

        // Re-sync persisted claims (e.g. `directive`) so a refreshed token picks up
        // anything added in AspNetUserClaims since the original authorization_code
        // sign-in, instead of only replaying whatever the old token principal
        // already carried.
        await AddPersistedClaimsAsync(identity, user);

        identity.SetDestinations(GetDestinations);

        return SignIn(new ClaimsPrincipal(identity), OpenIddictServerAspNetCoreDefaults.AuthenticationScheme);
    }

    /// <summary>
    /// Device Authorization Grant (RFC 8628 §3.4) — token endpoint half. The
    /// device polls here with <c>grant_type=device_code</c>; a principal only
    /// becomes attached to the device_code once the user approves the request
    /// via <see cref="DeviceController.Verify"/> (see that file for the full
    /// end-user-verification contract).
    ///
    /// Denial and expiry are handled by OpenIddict itself before this action
    /// even runs: when <see cref="DeviceController.Verify"/> returns
    /// <c>Forbid(..., Errors.AccessDenied, ...)</c>, OpenIddict's own
    /// RejectDeviceCodeEntry/RejectUserCodeEntry handlers mark the device_code
    /// token's status Rejected, and its own device-code validation then
    /// short-circuits subsequent polls with the matching standard error
    /// (access_denied/expired_token) without ever reaching here. A
    /// null/failed <see cref="HttpContext.AuthenticateAsync(string)"/> result
    /// at THIS point specifically means "valid, not expired, not rejected —
    /// just not approved yet", i.e. the RFC 8628 §3.5 authorization_pending
    /// case, so the client is expected to keep polling at the configured
    /// interval.
    /// </summary>
    private async Task<IActionResult> ExchangeForDeviceCodeAsync(OpenIddictRequest request)
    {
        var result = await HttpContext.AuthenticateAsync(OpenIddictServerAspNetCoreDefaults.AuthenticationScheme);
        if (result is not { Succeeded: true, Principal: not null })
        {
            return Forbid(
                authenticationSchemes: OpenIddictServerAspNetCoreDefaults.AuthenticationScheme,
                properties: new AuthenticationProperties(new Dictionary<string, string?>
                {
                    [OpenIddictServerAspNetCoreConstants.Properties.Error] = Errors.AuthorizationPending,
                    [OpenIddictServerAspNetCoreConstants.Properties.ErrorDescription] =
                        "The authorization request is still pending approval on the device verification page."
                }));
        }

        // NOT _userManager.GetUserAsync(result.Principal): that overload
        // resolves the subject via ClaimTypes.NameIdentifier, but
        // DeviceController.Verify (and every other grant in this file)
        // stores the subject under Claims.Subject ("sub") instead — so
        // GetUserAsync always returned null here, making every device_code
        // redemption fail with the (misleading, since it's actually a null
        // user) "no longer allowed to sign in" error below. This is why the
        // device flow never completed end-to-end (eval #B1): this bug
        // previously went undetected because no test drove a full
        // authorize-then-poll device_code redemption — see DeviceFlowTests.
        var subject = result.Principal.GetClaim(Claims.Subject);
        var user = subject is not null ? await _userManager.FindByIdAsync(subject) : null;
        if (user is null || !await _signInManager.CanSignInAsync(user))
        {
            return Forbid(
                authenticationSchemes: OpenIddictServerAspNetCoreDefaults.AuthenticationScheme,
                properties: new AuthenticationProperties(new Dictionary<string, string?>
                {
                    [OpenIddictServerAspNetCoreConstants.Properties.Error] = Errors.InvalidGrant,
                    [OpenIddictServerAspNetCoreConstants.Properties.ErrorDescription] =
                        "The user is no longer allowed to sign in."
                }));
        }

        // Fresh claims from current user state (roles/persisted claims may
        // have changed since the device_code was approved) — same rationale
        // as ExchangeForUserAsync's re-sync above.
        var identity = await BuildIdentityAsync(user);
        identity.SetScopes(result.Principal.GetScopes());
        identity.SetResources(await ToListAsync(_scopeManager.ListResourcesAsync(identity.GetScopes())));
        identity.SetDestinations(GetDestinations);

        return SignIn(new ClaimsPrincipal(identity), OpenIddictServerAspNetCoreDefaults.AuthenticationScheme);
    }

    private async Task<IActionResult> ExchangeForClientAsync(OpenIddictRequest request)
    {
        // client_credentials: no user, only the client identity itself.
        var application = await _applicationManager.FindByClientIdAsync(request.ClientId!) ??
            throw new InvalidOperationException("The application cannot be found.");

        var identity = new ClaimsIdentity(
            authenticationType: TokenValidationParameters.DefaultAuthenticationType,
            nameType: Claims.Name,
            roleType: Claims.Role);

        identity.SetClaim(Claims.Subject, (await _applicationManager.GetClientIdAsync(application))!);
        identity.SetClaim(Claims.Name, (await _applicationManager.GetDisplayNameAsync(application)) ?? request.ClientId!);
        identity.SetScopes(request.GetScopes());
        identity.SetResources(await ToListAsync(_scopeManager.ListResourcesAsync(identity.GetScopes())));
        identity.SetDestinations(GetDestinations);

        return SignIn(new ClaimsPrincipal(identity), OpenIddictServerAspNetCoreDefaults.AuthenticationScheme);
    }

    private async Task<IActionResult> ExchangeForPasswordAsync(OpenIddictRequest request)
    {
        var user = await _userManager.FindByNameAsync(request.Username!);

        // CheckPasswordSignInAsync (instead of a raw CheckPasswordAsync) enforces the
        // configured lockout policy on repeated failures. When the user does not
        // exist, SignInResult.Failed is used instead of short-circuiting, so the
        // response shape is identical to a wrong-password attempt (no user
        // enumeration via timing or error content).
        var result = user is not null
            ? await _signInManager.CheckPasswordSignInAsync(user, request.Password!, lockoutOnFailure: true)
            : Microsoft.AspNetCore.Identity.SignInResult.Failed;

        // Wrong password, locked out, not allowed to sign in (e.g. unconfirmed
        // email) and "no such user" all collapse to the SAME generic error: never
        // disclose which case occurred.
        if (user is null || !result.Succeeded || !await _signInManager.CanSignInAsync(user))
        {
            return Forbid(
                authenticationSchemes: OpenIddictServerAspNetCoreDefaults.AuthenticationScheme,
                properties: new AuthenticationProperties(new Dictionary<string, string?>
                {
                    [OpenIddictServerAspNetCoreConstants.Properties.Error] = Errors.InvalidGrant,
                    [OpenIddictServerAspNetCoreConstants.Properties.ErrorDescription] =
                        "Invalid username or password."
                }));
        }

        var identity = await BuildIdentityAsync(user);
        identity.SetScopes(request.GetScopes());
        identity.SetResources(await ToListAsync(_scopeManager.ListResourcesAsync(identity.GetScopes())));
        identity.SetDestinations(GetDestinations);

        return SignIn(new ClaimsPrincipal(identity), OpenIddictServerAspNetCoreDefaults.AuthenticationScheme);
    }

    /// <summary>
    /// RFC 8693 §4.1 "act" (actor) claim type. Not one of the well-known claim types
    /// exposed by <see cref="OpenIddictConstants.Claims"/>, so declared locally.
    /// </summary>
    private const string ActClaimType = "act";

    private async Task<IActionResult> ExchangeForTokenExchangeAsync(OpenIddictRequest request)
    {
        // P0 #4/#8 hardening: master kill switch + client allowlist, layered on
        // TOP of the OpenIddict-level Permissions.GrantTypes.TokenExchange
        // permission the server pipeline already enforces upstream (a client
        // without that permission never reaches this action at all). See
        // TokenExchangeOptions for defaults/rationale — both default to the
        // pre-existing behavior so TestDataSeeder's "test-exchange" client
        // (which already carries the OpenIddict permission) keeps working
        // without any appsettings change.
        if (!_tokenExchangeOptions.Enabled ||
            (_tokenExchangeOptions.AllowedClientIds.Count > 0 &&
             !_tokenExchangeOptions.AllowedClientIds.Contains(request.ClientId!)))
        {
            return Forbid(
                authenticationSchemes: OpenIddictServerAspNetCoreDefaults.AuthenticationScheme,
                properties: new AuthenticationProperties(new Dictionary<string, string?>
                {
                    [OpenIddictServerAspNetCoreConstants.Properties.Error] = Errors.UnauthorizedClient,
                    [OpenIddictServerAspNetCoreConstants.Properties.ErrorDescription] =
                        "This client is not allowed to perform token exchange."
                }));
        }

        // RFC 8693 (OAuth 2.0 Token Exchange). The incoming subject_token has already
        // been resolved and validated by OpenIddict's own server handlers (enabled via
        // AllowTokenExchangeFlow on the server builder), so — just like the
        // authorization_code/refresh_token grants above — its principal is retrieved
        // through the ASP.NET Core authentication handler instead of being parsed here.
        var result = await HttpContext.AuthenticateAsync(OpenIddictServerAspNetCoreDefaults.AuthenticationScheme);
        if (result is not { Succeeded: true, Principal: not null })
        {
            return Forbid(
                authenticationSchemes: OpenIddictServerAspNetCoreDefaults.AuthenticationScheme,
                properties: new AuthenticationProperties(new Dictionary<string, string?>
                {
                    [OpenIddictServerAspNetCoreConstants.Properties.Error] = Errors.InvalidGrant,
                    [OpenIddictServerAspNetCoreConstants.Properties.ErrorDescription] =
                        "The subject_token is missing, invalid or expired."
                }));
        }

        var subject = result.Principal.GetClaim(Claims.Subject);
        var user = subject is not null ? await _userManager.FindByIdAsync(subject) : null;

        if (user is null || !await _signInManager.CanSignInAsync(user))
        {
            return Forbid(
                authenticationSchemes: OpenIddictServerAspNetCoreDefaults.AuthenticationScheme,
                properties: new AuthenticationProperties(new Dictionary<string, string?>
                {
                    [OpenIddictServerAspNetCoreConstants.Properties.Error] = Errors.InvalidGrant,
                    [OpenIddictServerAspNetCoreConstants.Properties.ErrorDescription] =
                        "The subject_token no longer identifies a user that is allowed to sign in."
                }));
        }

        // NOTE (#4c): BuildIdentityAsync stages the subject's FULL role/claim
        // breadth onto this in-memory identity — the actual narrowing to
        // "only claims appropriate to the requested scopes" happens below via
        // GetDestinations, which (as of this same hardening pass) only routes
        // `role`/`name`/`email` to a token when the corresponding scope
        // (roles/profile/email) is present in the DELEGATED scope set set
        // just below — not the subject's original scope set. A narrowly-
        // scoped exchange (e.g. a client that only asked for a
        // resource-specific scope, no "roles") therefore no longer leaks the
        // subject's admin role breadth into the issued token, even though the
        // ClaimsIdentity object still carries it in memory for this request.
        var identity = await BuildIdentityAsync(user);

        // Delegated scopes are the intersection of what the calling client asked for
        // and what the subject_token itself carried; a client that doesn't request any
        // scope inherits the subject's full scope set as-is.
        var requestedScopes = request.GetScopes();
        var subjectScopes = result.Principal.GetScopes();
        identity.SetScopes(requestedScopes.Length > 0
            ? requestedScopes.Intersect(subjectScopes)
            : (IEnumerable<string>)subjectScopes);

        identity.SetResources(await ToListAsync(_scopeManager.ListResourcesAsync(identity.GetScopes())));

        // RFC 8693 §4.1: identify the acting party (the client performing the
        // exchange) with an "act" claim, NESTING any actor chain the
        // subject_token already carried (i.e. the subject_token was itself
        // already a delegated/exchanged token) instead of overwriting it —
        // otherwise a second hop of delegation silently drops who performed
        // the first exchange. The default branch of GetDestinations routes
        // unrecognized claim types to the access token only, which is what we
        // want here.
        var priorAct = result.Principal.GetClaim(ActClaimType);
        object actClaim = priorAct is not null
            ? new { sub = request.ClientId, act = JsonSerializer.Deserialize<JsonElement>(priorAct) }
            : new { sub = request.ClientId };
        identity.SetClaim(ActClaimType, JsonSerializer.SerializeToElement(actClaim));

        identity.SetDestinations(GetDestinations);

        return SignIn(new ClaimsPrincipal(identity), OpenIddictServerAspNetCoreDefaults.AuthenticationScheme);
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

        var claims = new Dictionary<string, object?>
        {
            [Claims.Subject] = await _userManager.GetUserIdAsync(user)
        };

        if (User.HasScope(Scopes.Email))
        {
            claims[Claims.Email] = await _userManager.GetEmailAsync(user);
            claims[Claims.EmailVerified] = await _userManager.IsEmailConfirmedAsync(user);
        }

        if (User.HasScope(Scopes.Profile))
        {
            claims[Claims.Name] = await _userManager.GetUserNameAsync(user);
            claims[Claims.PreferredUsername] = await _userManager.GetUserNameAsync(user);
        }

        if (User.HasScope(Scopes.Roles))
        {
            claims[Claims.Role] = await _userManager.GetRolesAsync(user);
        }

        return Ok(claims);
    }

    // -----------------------------------------------------------------------
    // /connect/endsession — OIDC RP-Initiated Logout 1.0.
    //
    // The GET handler forwards the endsession request to the UI confirmation
    // page hosted by sufficit-identity-ui (Blazor Server, /Account/Logout).
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
        var queryParams = new Dictionary<string, string?>
        {
            ["ReturnUrl"] = Request.Path + Request.QueryString
        };
        if (request?.IdTokenHint is { } idTokenHint)
            queryParams["id_token_hint"] = idTokenHint;
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

        await _signInManager.SignOutAsync();
        return SignOut(
            authenticationSchemes: OpenIddictServerAspNetCoreDefaults.AuthenticationScheme,
            properties: new AuthenticationProperties { RedirectUri = "/" });
    }

    // -----------------------------------------------------------------------
    // /connect/backchannel-logout — OIDC Back-Channel Logout 1.0.
    //
    // UNADVERTISED no-op acknowledgement stub (#N3). Discovery currently
    // publishes `backchannel_logout_supported=false` (see
    // ServiceCollectionExtensions.HandleConfigurationRequestContext) because
    // real distribution of logout_token to each RP's backchannel_logout_uri
    // is NOT implemented — this endpoint exists only to acknowledge receipt
    // if a federated RP ever posts one at it (server-to-server, not a
    // browser-submitted form, hence no antiforgery). Implementing real
    // distribution (queued fan-out to all registered RPs, with retry/audit)
    // is tracked as Onda B follow-up — until then, leaving this as 200 OK
    // is low-risk precisely because discovery says the feature is off.
    // -----------------------------------------------------------------------
    [HttpPost("~/connect/backchannel-logout")]
    [IgnoreAntiforgeryToken]
    public IActionResult BackchannelLogout()
    {
        // The OpenIddict validation handler already verified the logout_token
        // signature and sub before reaching this action. We accept it and
        // return 200 to acknowledge receipt.
        return Ok(new { status = "ok" });
    }

    // -----------------------------------------------------------------------
    // /connect/frontchannel-logout — OIDC Front-Channel Logout 1.0 landing.
    //
    // UNADVERTISED no-op landing page (#N3). Discovery publishes
    // `frontchannel_logout_supported=false` because real frontchannel logout
    // distribution (rendering iframes pointing at each RP's
    // frontchannel_logout_uri during sign-out) is NOT implemented. This page
    // only exists as the equivalent landing target if a federated RP ever
    // frames it (iframe GET, not a form POST — no antiforgery needed).
    // -----------------------------------------------------------------------
    [HttpGet("~/connect/frontchannel-logout")]
    [HttpPost("~/connect/frontchannel-logout")]
    [IgnoreAntiforgeryToken]
    public IActionResult FrontchannelLogout() => Content(
        @"<!DOCTYPE html><html><head><meta charset=""utf-8""><title>Frontchannel Logout</title></head>
<body><script>window.close(); window.location.replace('/');</script></body></html>",
        "text/html; charset=utf-8");

    // -----------------------------------------------------------------------
    // Helpers
    // -----------------------------------------------------------------------

    /// <summary>
    /// Claim types already derived from ASP.NET Core Identity in
    /// <see cref="BuildIdentityAsync"/>. Persisted claims (AspNetUserClaims) of
    /// these types are skipped when re-projecting the user's stored claims onto
    /// the identity, to avoid duplicating what was already set explicitly.
    /// </summary>
    private static readonly HashSet<string> ReservedClaimTypes = new(StringComparer.Ordinal)
    {
        Claims.Subject, Claims.Email, Claims.Name, Claims.PreferredUsername, Claims.Role
    };

    private async Task<ClaimsIdentity> BuildIdentityAsync(ApplicationUser user)
    {
        var identity = new ClaimsIdentity(
            authenticationType: TokenValidationParameters.DefaultAuthenticationType,
            nameType: Claims.Name,
            roleType: Claims.Role);

        identity.SetClaim(Claims.Subject, await _userManager.GetUserIdAsync(user))
                .SetClaim(Claims.Email, await _userManager.GetEmailAsync(user))
                .SetClaim(Claims.Name, await _userManager.GetUserNameAsync(user))
                .SetClaim(Claims.PreferredUsername, await _userManager.GetUserNameAsync(user))
                .SetClaims(Claims.Role, [.. await _userManager.GetRolesAsync(user)]);

        // Project persisted claims (AspNetUserClaims — e.g. `directive`, required by
        // downstream APIs for authorization) onto the token. Without this, the 5000+
        // claims stored against users never reach any token.
        await AddPersistedClaimsAsync(identity, user);

        return identity;
    }

    /// <summary>
    /// Copies the user's persisted claims (AspNetUserClaims) onto <paramref name="identity"/>,
    /// skipping <see cref="ReservedClaimTypes"/> and any claim already present with the exact
    /// same type+value (so re-syncing an already-populated identity, e.g. on token refresh,
    /// does not duplicate what a previous token cycle already added). Multiple distinct values
    /// for the same claim type (e.g. several `directive` values) are all preserved.
    /// </summary>
    private async Task AddPersistedClaimsAsync(ClaimsIdentity identity, ApplicationUser user)
    {
        var existing = new HashSet<(string Type, string Value)>(
            identity.Claims.Select(claim => (claim.Type, claim.Value)));

        foreach (var claim in await _userManager.GetClaimsAsync(user))
        {
            if (ReservedClaimTypes.Contains(claim.Type) || !existing.Add((claim.Type, claim.Value)))
            {
                continue;
            }

            identity.AddClaim(claim);
        }
    }

    /// <summary>
    /// Gates which token(s) — access, identity, or neither — each claim reaches
    /// (#4/#10). <c>name</c>/<c>email</c>/<c>role</c> are now bound to their
    /// matching scope (profile/email/roles respectively) for BOTH tokens: a
    /// claim only reaches ANY token when the caller was actually granted the
    /// corresponding scope. Previously these three always went to the access
    /// token unconditionally, regardless of scope — that's what let a
    /// narrowly-scoped token (e.g. a token-exchange delegation that only
    /// asked for a resource-specific scope) still carry the subject's full
    /// name/email/role breadth (only the scope SET was ever narrowed, never
    /// the claims — see ExchangeForTokenExchangeAsync).
    /// </summary>
    private static IEnumerable<string> GetDestinations(Claim claim)
    {
        switch (claim.Type)
        {
            case Claims.Name:
            case Claims.PreferredUsername:
                if (claim.Subject!.HasScope(Scopes.Profile))
                {
                    yield return Destinations.AccessToken;
                    yield return Destinations.IdentityToken;
                }
                yield break;

            case Claims.Email:
                if (claim.Subject!.HasScope(Scopes.Email))
                {
                    yield return Destinations.AccessToken;
                    yield return Destinations.IdentityToken;
                }
                yield break;

            case Claims.Role:
                if (claim.Subject!.HasScope(Scopes.Roles))
                {
                    yield return Destinations.AccessToken;
                    yield return Destinations.IdentityToken;
                }
                yield break;

            case "AspNet.Identity.SecurityStamp":
                yield break;

            default:
                // Custom persisted claims (AspNetUserClaims, e.g. `directive`)
                // have no scope of their own to gate on in this codebase —
                // routing them to the access token only (never the id_token)
                // is unchanged from before. KNOWN RESIDUAL GAP (eval #10): any
                // client that is a valid audience/resource for the token still
                // sees every persisted claim of this kind, not just ones
                // relevant to what it asked for. Closing that properly needs a
                // claim-type→scope allowlist (config-driven, analogous to
                // TokenExchangeOptions below) — deliberately NOT invented here
                // rather than guessing a mapping that could silently break
                // `directive` for existing resource servers (IntrospectionTests
                // pins today's behavior: `directive` must reach the access
                // token for a caller requesting only a plain custom scope,
                // with no profile/email/roles requested at all). Flagged as
                // follow-up hardening, not implemented in this pass.
                yield return Destinations.AccessToken;
                break;
        }
    }

    /// <summary>
    /// Materializes an <see cref="IAsyncEnumerable{T}"/> into a <see cref="List{T}"/>.
    /// Used because the OpenIddict managers expose results as IAsyncEnumerable and
    /// we don't want a hard dependency on the EF Core queryable extensions here.
    /// </summary>
    private static async Task<List<T>> ToListAsync<T>(IAsyncEnumerable<T> source)
    {
        var list = new List<T>();
        await foreach (var item in source)
        {
            list.Add(item);
        }
        return list;
    }
}

/// <summary>
/// Config-driven gate for the RFC 8693 token-exchange grant (P0 #4/#8 —
/// eval finding "token exchange sem policy"). Bound from the
/// <c>Sufficit:Identity:TokenExchange</c> configuration section. Read via a
/// plain <see cref="Microsoft.Extensions.Configuration.IConfiguration"/>
/// injection in <see cref="AuthorizationController"/> rather than being added
/// to <c>SufficitIdentityOptions</c>, since that type lives in
/// <c>src/sts/ServiceCollectionExtensions.cs</c> — no other project needs
/// to reference this type.
/// </summary>
public sealed class TokenExchangeOptions
{
    /// <summary>
    /// Master switch for the token-exchange grant (RFC 8693). Default
    /// <c>false</c> — secure-by-default (EVALUATION-2026-07-21 §5 P0 #8).
    /// Production environments that have signed off a delegation policy
    /// must opt-in explicitly via
    /// <c>Sufficit:Identity:TokenExchange:Enabled=true</c> AND configure
    /// <see cref="AllowedClientIds"/> to a closed allowlist. The "test-exchange"
    /// client used by <c>TokenExchangeTests</c> still works because the
    /// integration test factory overrides this default via test configuration.
    /// </summary>
    public bool Enabled { get; init; } = false;

    /// <summary>
    /// Client IDs allowed to act as the "actor" in a token exchange, on TOP of
    /// the OpenIddict-level <c>Permissions.GrantTypes.TokenExchange</c>
    /// permission already required on the calling application (enforced by
    /// the OpenIddict server pipeline itself, before this controller runs —
    /// a client without that permission never reaches
    /// <c>ExchangeForTokenExchangeAsync</c> at all). Empty/unconfigured
    /// (the default) = no additional restriction beyond that existing
    /// permission check, so TestDataSeeder's "test-exchange" client keeps
    /// working with zero appsettings changes. Configure this explicitly
    /// (<c>Sufficit:Identity:TokenExchange:AllowedClientIds</c>, a JSON
    /// array) to add a second, independent allowlist layer — defense in
    /// depth against a mis-provisioned application permission.
    /// </summary>
    public HashSet<string> AllowedClientIds { get; init; } = new(StringComparer.Ordinal);
}
