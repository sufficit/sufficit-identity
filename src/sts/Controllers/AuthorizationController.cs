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

    // `address` is an OIDC structured claim. Legacy user claims may use the
    // same name for arbitrary text, so preserve those values under Sufficit's
    // private namespace instead of asking the Identity service to understand
    // domain-specific address data.
    private const string LegacyAddressClaimType = "urn:sufficit:claim:address";

    private readonly IOpenIddictApplicationManager _applicationManager;
    private readonly IOpenIddictAuthorizationManager _authorizationManager;
    private readonly IOpenIddictScopeManager _scopeManager;
    private readonly IUserAvatarUrlResolver _avatarUrlResolver;
    private readonly SignInManager<ApplicationUser> _signInManager;
    private readonly UserManager<ApplicationUser> _userManager;
    private readonly TokenExchangeOptions _tokenExchangeOptions;
    private readonly IApplicationClaimDestinationPolicy _applicationClaimPolicy;
    private readonly Logout.IBackchannelLogoutDispatcher _backchannelLogoutDispatcher;
    private readonly Logout.IFrontchannelLogoutDispatcher _frontchannelLogoutDispatcher;
    private readonly SharedSignals.ISharedSignalsDispatcher _sharedSignalsDispatcher;
    private readonly Dpop.DpopProofValidator _dpopProofValidator;
    private readonly DpopOptions _dpopOptions;
    private readonly Fapi2Options _fapi2Options;
    private readonly Dpop.IDpopNonceStore _dpopNonceStore;
    private readonly IAntiforgery _antiforgery;
    private readonly ISubjectTokenProvenancePolicy _subjectTokenProvenancePolicy;
    private readonly IAuthenticationContextProjector _authenticationContextProjector;

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
        Dpop.DpopProofValidator dpopProofValidator,
        Dpop.IDpopNonceStore dpopNonceStore,
        ISubjectTokenProvenancePolicy subjectTokenProvenancePolicy,
        IAuthenticationContextProjector authenticationContextProjector)
    {
        _applicationManager = applicationManager;
        _authorizationManager = authorizationManager;
        _scopeManager = scopeManager;
        _avatarUrlResolver = avatarUrlResolver;
        _signInManager = signInManager;
        _userManager = userManager;
        _tokenExchangeOptions = configuration.GetSection("Sufficit:Identity:TokenExchange").Get<TokenExchangeOptions>()
            ?? new TokenExchangeOptions();
        _applicationClaimPolicy = applicationClaimPolicy;
        _antiforgery = antiforgery;
        _backchannelLogoutDispatcher = backchannelLogoutDispatcher;
        _frontchannelLogoutDispatcher = frontchannelLogoutDispatcher;
        _sharedSignalsDispatcher = sharedSignalsDispatcher;
        _dpopProofValidator = dpopProofValidator;
        _dpopNonceStore = dpopNonceStore;
        _subjectTokenProvenancePolicy = subjectTokenProvenancePolicy;
        _authenticationContextProjector = authenticationContextProjector;
        // DPoP options (item 3.1, RFC 9449).
        var rootOptions = configuration.GetSection("Sufficit:Identity")
            .Get<SufficitIdentityOptions>() ?? new SufficitIdentityOptions();
        _dpopOptions = rootOptions.Dpop;
        _fapi2Options = rootOptions.Fapi2;
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
        var authorizations = await ToListAsync(_authorizationManager.FindAsync(
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

        var identity = await BuildIdentityAsync(user, result.Principal);
        identity.SetScopes(requestedScopes);
        identity.SetResources(await ResolveResourcesAsync(identity, request));

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

        // DPoP (RFC 9449, item 3.1): when enabled, validate the DPoP proof
        // header once here, before dispatching to any grant branch. The proof
        // binds the issued token to the client's key (cnf.jkt). When
        // RequireForAllClients is set, a missing/invalid proof is fatal.
        // Branches that build the token identity attach the cnf claim via
        // ApplyDpopBinding below. OpenIddict 7.6 has no DPoP support, so this
        // lives in the controller (portable for a future move off OpenIddict).
        var requiresFapiDpop =
            Fapi.Fapi2Policy.Applies(_fapi2Options, request.ClientId) &&
            _fapi2Options.SenderConstraint == Fapi2SenderConstraint.Dpop;

        if (_dpopOptions.Enabled)
        {
            var dpopHeader = Request.Headers["DPoP"].ToString();
            string? expectedNonce = null;
            // DPoP nonce dance (RFC 9449 §8). When RequireNonce is on, the AS
            // challenges a cryptographically valid proof with a stateless
            // nonce bound to endpoint, client and proof key. Invalid/anonymous
            // traffic cannot rotate another client's challenge.
            if (_dpopOptions.RequireNonce && !string.IsNullOrWhiteSpace(dpopHeader))
            {
                var partition = BuildDpopNoncePartition(request, dpopHeader);
                var suppliedNonce = ExtractNonceFromHeader(dpopHeader);
                if (!_dpopNonceStore.IsValid(suppliedNonce, partition))
                {
                    var preliminaryProof = await _dpopProofValidator.ValidateAsync(
                        dpopHeader,
                        Request.Method,
                        Request.Scheme + "://" + Request.Host + Request.Path.Value,
                        expectedNonce: null,
                        HttpContext.RequestAborted);
                    if (preliminaryProof is null)
                    {
                        return Forbid(
                            authenticationSchemes: OpenIddictServerAspNetCoreDefaults.AuthenticationScheme,
                            properties: new AuthenticationProperties(new Dictionary<string, string?>
                            {
                                [OpenIddictServerAspNetCoreConstants.Properties.Error] = "invalid_dpop_proof",
                                [OpenIddictServerAspNetCoreConstants.Properties.ErrorDescription] =
                                    "A valid DPoP proof is required before a nonce challenge can be issued."
                            }));
                    }

                    var freshNonce = _dpopNonceStore.Issue(partition);
                    Response.Headers["DPoP-Nonce"] = freshNonce;
                    return Forbid(
                        authenticationSchemes: OpenIddictServerAspNetCoreDefaults.AuthenticationScheme,
                        properties: new AuthenticationProperties(new Dictionary<string, string?>
                        {
                            [OpenIddictServerAspNetCoreConstants.Properties.Error] = "use_dpop_nonce",
                            [OpenIddictServerAspNetCoreConstants.Properties.ErrorDescription] =
                                "A DPoP nonce is required. Retry the request with the DPoP-Nonce value in the proof's nonce claim."
                        }));
                }
                expectedNonce = suppliedNonce;
            }

            var proof = await _dpopProofValidator.ValidateAsync(
                dpopHeader,
                Request.Method,
                Request.Scheme + "://" + Request.Host + Request.Path.Value,
                expectedNonce,
                HttpContext.RequestAborted);

            if (proof is null && !string.IsNullOrWhiteSpace(dpopHeader))
            {
                return Forbid(
                    authenticationSchemes: OpenIddictServerAspNetCoreDefaults.AuthenticationScheme,
                    properties: new AuthenticationProperties(new Dictionary<string, string?>
                    {
                        [OpenIddictServerAspNetCoreConstants.Properties.Error] = "invalid_dpop_proof",
                        [OpenIddictServerAspNetCoreConstants.Properties.ErrorDescription] =
                            "The supplied DPoP proof is invalid and cannot be downgraded to bearer issuance."
                    }));
            }

            if (proof is null &&
                (_dpopOptions.RequireForAllClients || requiresFapiDpop))
            {
                return Forbid(
                    authenticationSchemes: OpenIddictServerAspNetCoreDefaults.AuthenticationScheme,
                    properties: new AuthenticationProperties(new Dictionary<string, string?>
                    {
                        [OpenIddictServerAspNetCoreConstants.Properties.Error] = Errors.InvalidClient,
                        [OpenIddictServerAspNetCoreConstants.Properties.ErrorDescription] =
                            "A valid DPoP proof header is required for this token request."
                    }));
            }
            // Stash the proof for branches to attach; null when absent (accepted
            // when not required). HttpContext.Items is per-request safe.
            HttpContext.Items["dpop.proof"] = proof;
        }

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

        // For refresh-token grants, build a fresh identity from current user
        // state instead of inheriting claims from the old token principal.
        // Finding #9: the old code replayed claims from the previous token,
        // so a revoked `directive` claim survived until the refresh token
        // expired (up to 14 days). Building fresh ensures deleted claims are
        // purged on every refresh.
        ClaimsIdentity identity;
        if (request.IsRefreshTokenGrantType())
        {
            identity = await BuildIdentityAsync(user, result.Principal);

            // Preserve the session id from the grant principal — BuildIdentityAsync
            // reads it from the HTTP context User (the cookie), which is absent in
            // a machine-to-machine token refresh. The grant principal carries the
            // original sid from the authorization-code sign-in.
            var grantSid = result.Principal!.GetClaim(SessionIdClaimType);
            if (!string.IsNullOrWhiteSpace(grantSid))
            {
                identity.SetClaim(SessionIdClaimType, grantSid);
            }

            // Restore the granted scopes and resources onto the freshly-built
            // identity. BuildIdentityAsync starts from current user state and
            // does NOT inherit the grant principal's `oi_scp`/`oi_resrc`, so
            // without this the refreshed token carries NO scopes — which makes
            // GetDestinations drop every scope-gated claim (e.g. `directive`,
            // gated behind the `directives` scope) and leaves the token with no
            // audience. The result: refreshed access tokens were rejected by
            // resource servers (403) even though the initial device-code /
            // auth-code token worked. Mirrors ExchangeForDeviceCodeAsync. The
            // auth-code branch below instead inherits these from the code
            // principal's claims, so it does not need this.
            // Tokens issued by the briefly deployed pre-fix refresh path may
            // themselves carry no scopes. Recover only the scopes persisted on
            // that token's original authorization so existing sessions heal on
            // their next refresh without broadening the grant.
            identity.SetScopes(await RefreshGrantScopeResolver.ResolveAsync(
                result.Principal!,
                _authorizationManager,
                HttpContext.RequestAborted));
            identity.SetResources(await ResolveResourcesAsync(identity, request));
        }
        else
        {
            // Authorization-code grant: inherit from the code principal (which
            // was just built moments ago at /connect/authorize).
            identity = new ClaimsIdentity(result.Principal!.Claims,
                authenticationType: TokenValidationParameters.DefaultAuthenticationType,
                nameType: Claims.Name,
                roleType: Claims.Role);

            // Re-sync persisted claims for the auth-code path too.
            await AddPersistedClaimsAsync(identity, user);
        }

        if ((request.IsAuthorizationCodeGrantType() || request.IsRefreshTokenGrantType()) &&
            !HasMatchingDpopBinding(result.Principal!))
        {
            return Forbid(
                authenticationSchemes: OpenIddictServerAspNetCoreDefaults.AuthenticationScheme,
                properties: new AuthenticationProperties(new Dictionary<string, string?>
                {
                    [OpenIddictServerAspNetCoreConstants.Properties.Error] = Errors.InvalidGrant,
                    [OpenIddictServerAspNetCoreConstants.Properties.ErrorDescription] =
                        "The DPoP proof does not match the key bound to the authorization grant."
                }));
        }

        // For refresh grants, scope/DPoP/session are carried from the grant
        // principal (OpenIddict restores them). For auth-code grants, they
        // were set on the code principal above. Either way, the identity now
        // reflects current user state.

        // Finding #15: for refresh-token grants, preserve the original DPoP
        // binding from the grant principal so the token cannot be re-bound to
        // a different key on refresh. ApplyDpopBinding reads from
        // HttpContext.Items["dpop.proof"] (the current request's proof), which
        // is correct for initial issuance but would overwrite the original
        // binding on refresh if the client presents a different key.
        if (request.IsRefreshTokenGrantType())
        {
            var originalBinding = result.Principal!.GetClaim(
                Dpop.DpopProofValidator.BindingThumbprintClaimType);
            if (!string.IsNullOrWhiteSpace(originalBinding))
            {
                identity.SetClaim(
                    Dpop.DpopProofValidator.BindingThumbprintClaimType,
                    originalBinding);
            }
        }
        else
        {
            ApplyDpopBinding(identity);
        }
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
        var identity = await BuildIdentityAsync(user, result.Principal);
        identity.SetScopes(result.Principal.GetScopes());
        identity.SetResources(await ResolveResourcesAsync(identity, request));
        ApplyDpopBinding(identity);
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
        identity.SetResources(await ResolveResourcesAsync(identity, request));
        ApplyDpopBinding(identity);
        identity.SetDestinations(GetDestinations);

        return SignIn(new ClaimsPrincipal(identity), OpenIddictServerAspNetCoreDefaults.AuthenticationScheme);
    }

    /// <summary>
    /// Attaches the DPoP confirmation (<c>cnf</c>) claim to the token identity
    /// when the request carried a valid DPoP proof (RFC 9449 §7.2). The claim
    /// is a JSON object <c>{"jkt":"&lt;thumbprint&gt;"}</c> that resource
    /// servers use to reject the token unless a later request presents a proof
    /// signed by the matching key. No-op when DPoP is disabled or the proof
    /// was absent/invalid (and not required).
    /// </summary>
    private void ApplyDpopBinding(ClaimsIdentity identity)
    {
        if (HttpContext.Items["dpop.proof"] is not Dpop.DpopProof proof) return;

        // OpenIddict strips inherited cnf claims while preparing token
        // principals. Carry the thumbprint in a non-emitted marker; the custom
        // ProcessSignIn handler attaches cnf after that preparation stage.
        identity.SetClaim(
            Dpop.DpopProofValidator.BindingThumbprintClaimType,
            proof.KeyThumbprint);
    }

    private bool HasMatchingDpopBinding(ClaimsPrincipal principal)
    {
        var boundThumbprint = principal.GetClaim(
            Dpop.DpopProofValidator.BindingThumbprintClaimType);
        if (string.IsNullOrEmpty(boundThumbprint)) return true;
        if (HttpContext.Items["dpop.proof"] is not Dpop.DpopProof proof) return false;
        return string.Equals(
            boundThumbprint,
            proof.KeyThumbprint,
            StringComparison.Ordinal);
    }

    private string BuildDpopNoncePartition(
        OpenIddictRequest request,
        string dpopHeader)
    {
        Dpop.DpopProofValidator.TryGetKeyThumbprint(dpopHeader, out var thumbprint);
        return string.Join('|',
            Request.Path.Value ?? "/connect/token",
            request.ClientId ?? "<anonymous>",
            string.IsNullOrWhiteSpace(thumbprint) ? "<unknown-key>" : thumbprint);
    }

    /// <summary>
    /// Best-effort extraction of the <c>nonce</c> claim from a DPoP proof
    /// header, without full validation. The value is accepted only after the
    /// partition-bound nonce protector and full proof validator approve it.
    /// </summary>
    private static string? ExtractNonceFromHeader(string? dpopHeader)
    {
        if (string.IsNullOrWhiteSpace(dpopHeader)) return null;
        try
        {
            var jwt = new Microsoft.IdentityModel.JsonWebTokens.JsonWebToken(dpopHeader);
            return jwt.TryGetPayloadValue("nonce", out string nonce) ? nonce : null;
        }
        catch
        {
            return null;
        }
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

        var identity = await BuildIdentityAsync(
            user,
            CreateAuthenticationContextPrincipal(
                ["pwd"],
                "urn:sufficit:acr:loa1"));
        identity.SetScopes(request.GetScopes());
        identity.SetResources(await ResolveResourcesAsync(identity, request));
        ApplyDpopBinding(identity);
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

        // Finding #1 (confused-deputy, RFC 8707): when AllowedClientIds is
        // configured (non-empty), the operator has defined a closed set of
        // clients authorized to exchange tokens. The subject_token's `azp`
        // must match one of those authorized clients — preventing a client
        // outside the allowlist from presenting a token it captured elsewhere.
        // When AllowedClientIds is empty (back-compat default), the OpenIddict
        // grant permission alone gates exchange (the original pre-finding posture).
        if (_tokenExchangeOptions.AllowedClientIds.Count > 0)
        {
            var provenance = _subjectTokenProvenancePolicy.Evaluate(
                result.Principal,
                _tokenExchangeOptions.AllowedClientIds,
                _tokenExchangeOptions.ProvenanceMode);
            if (provenance.ShouldReject)
            {
                return Forbid(
                    authenticationSchemes: OpenIddictServerAspNetCoreDefaults.AuthenticationScheme,
                    properties: new AuthenticationProperties(new Dictionary<string, string?>
                    {
                        [OpenIddictServerAspNetCoreConstants.Properties.Error] = Errors.InvalidGrant,
                        [OpenIddictServerAspNetCoreConstants.Properties.ErrorDescription] =
                            "The subject_token was issued to a client not in the TokenExchange allowlist."
                    }));
            }
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
        var identity = await BuildIdentityAsync(user, result.Principal);

        // Delegated scopes are the intersection of what the calling client asked for
        // and what the subject_token itself carried; a client that doesn't request any
        // scope inherits the subject's full scope set as-is.
        var requestedScopes = request.GetScopes();
        var subjectScopes = result.Principal.GetScopes();
        identity.SetScopes(requestedScopes.Length > 0
            ? requestedScopes.Intersect(subjectScopes)
            : (IEnumerable<string>)subjectScopes);

        var delegatedResources = (await ResolveResourcesAsync(identity, request))
            .ToHashSet(StringComparer.Ordinal);
        var subjectResources = result.Principal.GetResources()
            .Concat(result.Principal.GetAudiences())
            .ToHashSet(StringComparer.Ordinal);
        var requestedResources = request.GetResources();
        if (requestedResources.Any(resource => !subjectResources.Contains(resource)))
        {
            return Forbid(
                authenticationSchemes: OpenIddictServerAspNetCoreDefaults.AuthenticationScheme,
                properties: new AuthenticationProperties(new Dictionary<string, string?>
                {
                    [OpenIddictServerAspNetCoreConstants.Properties.Error] = Errors.InvalidTarget,
                    [OpenIddictServerAspNetCoreConstants.Properties.ErrorDescription] =
                        "The requested resource is not authorized by the subject_token."
                }));
        }
        identity.SetResources(delegatedResources.Intersect(subjectResources));

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

        ApplyDpopBinding(identity);
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

        var redirectUri = frontchannelContext is null
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

    // -----------------------------------------------------------------------
    // Helpers
    // -----------------------------------------------------------------------

    /// <summary>
    /// Claim types already derived from ASP.NET Core Identity in
    /// <see cref="BuildIdentityAsync"/>. Persisted claims (AspNetUserClaims) of
    /// these types are skipped when re-projecting the user's stored claims onto
    /// the identity, to avoid duplicating what was already set explicitly. The
    /// OIDC <c>address</c> claim is handled separately and remapped to the
    /// private Sufficit namespace when it comes from a legacy persisted claim,
    /// because OpenIddict requires the standard name to contain a structured
    /// JSON object.
    /// </summary>
    private static readonly HashSet<string> ReservedClaimTypes = new(StringComparer.Ordinal)
    {
        Claims.Subject,
        Claims.Email,
        Claims.Name,
        Claims.PreferredUsername,
        Claims.Role
    };

    private static ClaimsPrincipal CreateAuthenticationContextPrincipal(
        IReadOnlyCollection<string> methods,
        string authenticationContextClass)
    {
        var identity = new ClaimsIdentity();
        identity.AddClaims(methods.Select(method => new Claim(
            AuthenticationContextProjector.AuthenticationMethodClaimType,
            method)));
        identity.AddClaim(new Claim(
            AuthenticationContextProjector.AuthenticationContextClassClaimType,
            authenticationContextClass));
        identity.AddClaim(new Claim(
            AuthenticationContextProjector.AuthenticationTimeClaimType,
            DateTimeOffset.UtcNow.ToUnixTimeSeconds().ToString(
                System.Globalization.CultureInfo.InvariantCulture)));
        return new ClaimsPrincipal(identity);
    }

    private async Task<ClaimsIdentity> BuildIdentityAsync(
        ApplicationUser user,
        ClaimsPrincipal? authenticationContext = null)
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

        var sessionId = User.GetClaim(SessionIdClaimType);
        if (!string.IsNullOrWhiteSpace(sessionId))
        {
            identity.SetClaim(SessionIdClaimType, sessionId);
        }

        _authenticationContextProjector.Project(
            authenticationContext ?? User,
            identity);

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
            if (claim.Type == Claims.Address)
            {
                var remapped = new Claim(
                    LegacyAddressClaimType,
                    claim.Value,
                    ClaimValueTypes.String,
                    claim.Issuer);

                if (existing.Add((remapped.Type, remapped.Value)))
                {
                    identity.AddClaim(remapped);
                }

                continue;
            }

            if (ReservedClaimTypes.Contains(claim.Type) || !existing.Add((claim.Type, claim.Value)))
            {
                continue;
            }

            identity.AddClaim(claim);
        }
    }

    /// <summary>
    /// Resolves the resource/audience set for an issued token: the UNION of
    /// (a) resources derived from the granted scopes (via ListResourcesAsync —
    /// the pre-existing behavior) and (b) any <c>resource</c> indicators the
    /// client explicitly requested (RFC 8707, item 4.2). Without (b), a token
    /// requested for <c>resource=https://mcp.example</c> would NOT carry that
    /// audience, defeating audience-binding (the MCP/server confused-deputy
    /// mitigation). OpenIddict validates the requested resource against the
    /// client's <c>oi_rprm</c> permission BEFORE this runs, so only
    /// authorized resources reach here.
    /// </summary>
    private async Task<IEnumerable<string>> ResolveResourcesAsync(
        ClaimsIdentity identity, OpenIddictRequest? request)
    {
        var resources = await ToListAsync(_scopeManager.ListResourcesAsync(identity.GetScopes()));
        if (request is not null)
        {
            // request.GetResources() returns the explicit resource parameter
            // values (RFC 8707 §2). Union them in; SetResources dedupes.
            foreach (var resource in request.GetResources())
            {
                if (!resources.Contains(resource, StringComparer.Ordinal))
                {
                    resources.Add(resource);
                }
            }
        }
        return resources;
    }

    /// <summary>
    /// Gates which token(s) — access, identity, or neither — each claim reaches
    /// (#4/#10). <c>name</c>/<c>email</c>/<c>role</c> are bound to their
    /// matching scope (profile/email/roles respectively) for BOTH tokens: a
    /// claim only reaches ANY token when the caller was actually granted the
    /// corresponding scope. Custom persisted claims are handled only by the
    /// config-driven <see cref="_claimScopeMap"/> (item 2.5 [M5]): a claim
    /// type present in the map reaches the access and identity tokens if the
    /// subject was granted the mapped scope. The Identity service does not
    /// assign meaning to application-specific claim names.
    /// </summary>
    private IEnumerable<string> GetDestinations(Claim claim)
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

            case AuthenticationContextProjector.AuthenticationMethodClaimType:
            case AuthenticationContextProjector.AuthenticationContextClassClaimType:
            case AuthenticationContextProjector.AuthenticationTimeClaimType:
                yield return Destinations.AccessToken;
                yield return Destinations.IdentityToken;
                yield break;

            case SessionIdClaimType:
                // OIDC Front-/Back-Channel Logout session correlation. sid is
                // an ID Token claim; it is not needed by resource servers.
                yield return Destinations.IdentityToken;
                yield break;

            case "AspNet.Identity.SecurityStamp":
                yield break;

            case Dpop.DpopProofValidator.ConfirmationClaimType:
                // DPoP confirmation (RFC 9449 §7.2): route to the access token
                // only — resource servers validate it; the id_token is for the
                // client and must not carry the sender-binding thumbprint.
                yield return Destinations.AccessToken;
                yield break;

            case Dpop.DpopProofValidator.BindingThumbprintClaimType:
                // Internal handoff consumed by AttachDpopConfirmation after
                // OpenIddict prepares the concrete token principals.
                yield break;

            default:
                // Custom persisted claims (AspNetUserClaims).
                // Item 2.5 [M5] (closes eval #10): if the claim type is in the
                // config-driven _claimScopeMap, it reaches the access token and
                // id_token when the subject was granted the mapped scope; otherwise
                // it is dropped. Claim types NOT in the map fall through to the
                // pre-existing behavior (access token, never id_token), so an
                // empty map (the default) is byte-identical to before — and
                // callers requesting only a plain custom scope still holds.
                foreach (var destination in _applicationClaimPolicy.GetDestinations(
                    claim, includeIdentityToken: true))
                    yield return destination;
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
    /// Master switch for the token-exchange grant (RFC 8693). It remains on by
    /// default for rolling-upgrade compatibility; OpenIddict's per-application
    /// grant permission and the attenuation policy still apply. Operators can
    /// add <see cref="AllowedClientIds"/> as a second client boundary.
    /// </summary>
    public bool Enabled { get; init; } = true;

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

    /// <summary>
    /// Observe preserves legacy subject tokens that have no unambiguous
    /// authorized-party identity while emitting the future denial. Enforce
    /// rejects them whenever <see cref="AllowedClientIds"/> is configured.
    /// </summary>
    public SecurityPolicyEnforcementMode ProvenanceMode { get; init; } =
        SecurityPolicyEnforcementMode.Observe;
}
