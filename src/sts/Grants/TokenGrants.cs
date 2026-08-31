using System.Security.Claims;
using System.Text.Json;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.AspNetCore.Mvc;
using OpenIddict.Abstractions;
using OpenIddict.Server.AspNetCore;
using Sufficit.Identity.Core.Entities;
using static OpenIddict.Abstractions.OpenIddictConstants;

namespace Sufficit.Identity.STS.Grants;

/// <summary>
/// Everything a token-endpoint grant branch needs (A2, eval 2026-08-14).
/// The DPoP proof is validated ONCE by the dispatcher and handed to the
/// handler explicitly — handlers never re-parse the header.
/// </summary>
public sealed record TokenGrantContext(
    HttpContext HttpContext,
    OpenIddictRequest Request,
    Dpop.DpopProof? Proof,
    bool RequiresFapiDpop,
    GrantOperations Operations);

/// <summary>
/// One implementation per OAuth grant family. The dispatcher owns the
/// cross-cutting preamble (DPoP nonce dance, proof validation, FAPI
/// binding flags), so a handler only implements its grant's semantics.
/// Adding a grant (e.g. RFC 7523 assertions or CIMD) means adding a class
/// and a DI registration — <c>AuthorizationController.Exchange</c> never
/// grows again.
/// </summary>
public interface ITokenGrantHandler
{
    /// <summary>Grant type identifiers this handler serves (e.g.
    /// authorization_code). Named HandledGrantTypes because the file uses
    /// <c>using static OpenIddictConstants</c>, whose GrantTypes constants
    /// would collide with a same-named member.</summary>
    IReadOnlyCollection<string> HandledGrantTypes { get; }

    Task<IActionResult> HandleAsync(TokenGrantContext context);
}

/// <summary>
/// Dispatches <c>/connect/token</c>: validates the DPoP proof once (nonce
/// dance included), resolves the grant handler and invokes it. Replaces the
/// grant switch that used to live in AuthorizationController.Exchange.
/// </summary>
public sealed class TokenGrantDispatcher(
    Dpop.DpopProofValidator dpopProofValidator,
    Dpop.IDpopNonceStore dpopNonceStore,
    IEnumerable<ITokenGrantHandler> handlers,
    // The STS composition registers the BOUND options instance as a
    // singleton (AddSingleton(options)); injecting IOptions<> here would
    // yield an unconfigured default and silently disable the DPoP preamble.
    SufficitIdentityOptions rootOptions)
{
    private readonly IReadOnlyDictionary<string, ITokenGrantHandler> _handlers =
        handlers.SelectMany(handler => handler.HandledGrantTypes,
                (handler, grant) => (grant, handler))
            .ToDictionary(pair => pair.grant, pair => pair.handler,
                StringComparer.Ordinal);

    public async Task<IActionResult> DispatchAsync(
        HttpContext httpContext,
        OpenIddictRequest request)
    {
        var options = rootOptions;
        var requiresFapiDpop =
            Fapi.Fapi2Policy.Applies(options.Fapi2, request.ClientId)
            && options.Fapi2.SenderConstraint == Fapi2SenderConstraint.Dpop;

        // ---- DPoP preamble (RFC 9449) — runs for EVERY grant exactly once.
        // When enabled, the proof binds the issued token to the client's key
        // (cnf.jkt). When RequireForAllClients is set, a missing/invalid proof
        // is fatal. OpenIddict 7.6 has no DPoP support, so this lives here.
        Dpop.DpopProof? proof = null;
        if (options.Dpop.Enabled)
        {
            var dpopHeader = httpContext.Request.Headers["DPoP"].ToString();
            string? expectedNonce = null;
            // DPoP nonce dance (RFC 9449 §8). When RequireNonce is on, the AS
            // challenges a cryptographically valid proof with a stateless
            // nonce bound to endpoint, client and proof key. Invalid/anonymous
            // traffic cannot rotate another client's challenge.
            if (options.Dpop.RequireNonce && !string.IsNullOrWhiteSpace(dpopHeader))
            {
                var partition = BuildDpopNoncePartition(request, dpopHeader,
                    httpContext.Request.Path.Value ?? "/connect/token");
                var suppliedNonce = GrantOperations.ExtractNonceFromHeader(dpopHeader);
                if (!dpopNonceStore.IsValid(suppliedNonce, partition))
                {
                    var preliminaryProof = await dpopProofValidator.ValidateAsync(
                        dpopHeader,
                        httpContext.Request.Method,
                        httpContext.Request.Scheme + "://" + httpContext.Request.Host
                            + httpContext.Request.Path.Value,
                        expectedNonce: null,
                        httpContext.RequestAborted);
                    if (preliminaryProof is null)
                    {
                        return ForbidError("invalid_dpop_proof",
                            "A valid DPoP proof is required before a nonce challenge can be issued.");
                    }

                    var freshNonce = dpopNonceStore.Issue(partition);
                    httpContext.Response.Headers["DPoP-Nonce"] = freshNonce;
                    return ForbidError("use_dpop_nonce",
                        "A DPoP nonce is required. Retry the request with the DPoP-Nonce value in the proof's nonce claim.");
                }
                expectedNonce = suppliedNonce;
            }

            proof = await dpopProofValidator.ValidateAsync(
                dpopHeader,
                httpContext.Request.Method,
                httpContext.Request.Scheme + "://" + httpContext.Request.Host
                    + httpContext.Request.Path.Value,
                expectedNonce,
                httpContext.RequestAborted);

            if (proof is null && !string.IsNullOrWhiteSpace(dpopHeader))
            {
                return ForbidError("invalid_dpop_proof",
                    "The supplied DPoP proof is invalid and cannot be downgraded to bearer issuance.");
            }

            if (proof is null && (options.Dpop.RequireForAllClients || requiresFapiDpop))
            {
                return ForbidError(Errors.InvalidClient,
                    "A valid DPoP proof header is required for this token request.");
            }
        }

        var grantType = request.GrantType;
        if (grantType is null
            || !_handlers.TryGetValue(grantType, out var handler))
        {
            return ForbidError(Errors.UnsupportedGrantType, null);
        }

        // The operations service is scoped per request alongside the handlers.
        var operations = httpContext.RequestServices
            .GetRequiredService<GrantOperations>();
        return await handler.HandleAsync(new TokenGrantContext(
            httpContext, request, proof, requiresFapiDpop, operations));
    }

    internal static string BuildDpopNoncePartition(
        OpenIddictRequest request,
        string dpopHeader,
        string path)
    {
        Dpop.DpopProofValidator.TryGetKeyThumbprint(dpopHeader, out var thumbprint);
        return string.Join('|',
            path,
            request.ClientId ?? "<anonymous>",
            string.IsNullOrWhiteSpace(thumbprint) ? "<unknown-key>" : thumbprint);
    }

    internal static ForbidResult ForbidError(
        string error,
        string? errorDescription)
    {
        var properties = new Microsoft.AspNetCore.Authentication.AuthenticationProperties(
            new Dictionary<string, string?>());
        properties.Items[OpenIddictServerAspNetCoreConstants.Properties.Error] = error;
        if (errorDescription is not null)
        {
            properties.Items[OpenIddictServerAspNetCoreConstants.Properties.ErrorDescription] =
                errorDescription;
        }
        return new ForbidResult(
            [OpenIddictServerAspNetCoreDefaults.AuthenticationScheme],
            properties);
    }
}

/// <summary>
/// authorization_code + refresh_token: the user-centered grants. For
/// refresh, a fresh identity is rebuilt from CURRENT user state (deleted
/// claims are purged, roles re-synced) and the sid + DPoP binding survive
/// from the original grant principal.
/// </summary>
public sealed class UserTokenGrantsHandler : ITokenGrantHandler
{
    public IReadOnlyCollection<string> HandledGrantTypes { get; } =
        [GrantTypes.AuthorizationCode, GrantTypes.RefreshToken];

    public async Task<IActionResult> HandleAsync(TokenGrantContext context)
    {
        var (httpContext, request, proof, ops) =
            (context.HttpContext, context.Request, context.Proof, context.Operations);

        var result = await httpContext.AuthenticateAsync(
            OpenIddictServerAspNetCoreDefaults.AuthenticationScheme);
        var user = await ops.UserManager.FindByIdAsync(
            result.Principal!.GetClaim(Claims.Subject)!);

        if (user is null || !await ops.SignInManager.CanSignInAsync(user))
        {
            return TokenGrantDispatcher.ForbidError(Errors.InvalidGrant,
                "The token is no longer valid or the user is no longer allowed to sign in.");
        }

        var grantedScopes = request.IsRefreshTokenGrantType()
            ? await RefreshGrantScopeResolver.ResolveAsync(
                result.Principal!,
                httpContext.RequestServices.GetRequiredService<IOpenIddictAuthorizationManager>(),
                httpContext.RequestAborted)
            : result.Principal!.GetScopes();
        grantedScopes = ops.ResolveImplicitMcpScopes(
            request.ClientId,
            grantedScopes);
        var entitlementResult = await ops.ProvisionScopeEntitlementsAsync(
            user,
            grantedScopes,
            httpContext.RequestAborted);
        if (!entitlementResult.Succeeded)
        {
            return TokenGrantDispatcher.ForbidError(
                "temporarily_unavailable",
                "The requested product access could not be activated. Please retry.");
        }

        ClaimsIdentity identity;
        if (request.IsRefreshTokenGrantType())
        {
            // Finding #9 (kept from the controller): rebuild from current user
            // state instead of replaying claims from the previous token, so a
            // revoked claim does not survive until refresh expiry.
            identity = await ops.BuildIdentityAsync(
                user,
                result.Principal,
                httpContext.User);

            // Preserve the session id from the grant principal — the HTTP
            // context user (cookie) is absent in a machine-to-machine refresh.
            var grantSid = result.Principal!.GetClaim(GrantOperations.SessionIdClaimType);
            if (!string.IsNullOrWhiteSpace(grantSid))
            {
                identity.SetClaim(GrantOperations.SessionIdClaimType, grantSid);
            }

            // Restore granted scopes/resources: BuildIdentityAsync starts from
            // current user state and does NOT inherit oi_scp/oi_resrc.
            identity.SetScopes(grantedScopes);
            identity.SetResources(await ops.ResolveResourcesAsync(identity, request));
        }
        else
        {
            // Authorization-code grant: inherit from the code principal (built
            // moments ago at /connect/authorize), then re-sync persisted claims.
            identity = new ClaimsIdentity(result.Principal!.Claims,
                authenticationType: Microsoft.IdentityModel.Tokens.TokenValidationParameters.DefaultAuthenticationType,
                nameType: Claims.Name,
                roleType: Claims.Role);

            await ops.AddPersistedClaimsAsync(identity, user);
        }

        if (!GrantOperations.HasMatchingDpopBinding(result.Principal!, proof))
        {
            return TokenGrantDispatcher.ForbidError(Errors.InvalidGrant,
                "The DPoP proof does not match the key bound to the authorization grant.");
        }

        // Finding #15: on refresh, preserve the ORIGINAL DPoP binding so the
        // token cannot be re-bound to a different key.
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
            GrantOperations.ApplyDpopBinding(identity, proof);
        }
        identity.SetDestinations(ops.GetDestinations);

        return new SignInResult(
            OpenIddictServerAspNetCoreDefaults.AuthenticationScheme,
            new ClaimsPrincipal(identity));
    }
}

/// <summary>
/// Device Authorization Grant (RFC 8628 §3.4) — token-endpoint half.
/// Denial/expiry are rejected by OpenIddict before this runs; a null
/// principal here specifically means authorization_pending.
/// </summary>
public sealed class DeviceCodeGrantHandler : ITokenGrantHandler
{
    public IReadOnlyCollection<string> HandledGrantTypes { get; } =
        [GrantTypes.DeviceCode];

    public async Task<IActionResult> HandleAsync(TokenGrantContext context)
    {
        var (httpContext, request, proof, ops) =
            (context.HttpContext, context.Request, context.Proof, context.Operations);

        var result = await httpContext.AuthenticateAsync(
            OpenIddictServerAspNetCoreDefaults.AuthenticationScheme);
        if (result is not { Succeeded: true, Principal: not null })
        {
            return TokenGrantDispatcher.ForbidError(Errors.AuthorizationPending,
                "The authorization request is still pending approval on the device verification page.");
        }

        // NOT UserManager.GetUserAsync: that overload resolves via
        // ClaimTypes.NameIdentifier, but DeviceController stores the subject
        // under Claims.Subject ("sub") — GetUserAsync always returned null
        // here (eval #B1).
        var subject = result.Principal.GetClaim(Claims.Subject);
        var user = subject is not null
            ? await ops.UserManager.FindByIdAsync(subject)
            : null;
        if (user is null || !await ops.SignInManager.CanSignInAsync(user))
        {
            return TokenGrantDispatcher.ForbidError(Errors.InvalidGrant,
                "The user is no longer allowed to sign in.");
        }

        var grantedScopes = ops.ResolveImplicitMcpScopes(
            request.ClientId,
            result.Principal.GetScopes());
        var entitlementResult = await ops.ProvisionScopeEntitlementsAsync(
            user,
            grantedScopes,
            httpContext.RequestAborted);
        if (!entitlementResult.Succeeded)
        {
            return TokenGrantDispatcher.ForbidError(
                "temporarily_unavailable",
                "The requested product access could not be activated. Please retry.");
        }

        // Fresh claims from current user state (roles/persisted claims may
        // have changed since the device_code was approved).
        var identity = await ops.BuildIdentityAsync(
            user, result.Principal, httpContext.User);
        identity.SetScopes(grantedScopes);
        identity.SetResources(await ops.ResolveResourcesAsync(identity, request));
        GrantOperations.ApplyDpopBinding(identity, proof);
        identity.SetDestinations(ops.GetDestinations);

        return new SignInResult(
            OpenIddictServerAspNetCoreDefaults.AuthenticationScheme,
            new ClaimsPrincipal(identity));
    }
}

/// <summary>client_credentials: no user, only the client identity itself.</summary>
public sealed class ClientCredentialsGrantHandler : ITokenGrantHandler
{
    public IReadOnlyCollection<string> HandledGrantTypes { get; } =
        [GrantTypes.ClientCredentials];

    public async Task<IActionResult> HandleAsync(TokenGrantContext context)
    {
        var (request, proof, ops) = (context.Request, context.Proof, context.Operations);

        var application = await ops.ApplicationManager.FindByClientIdAsync(request.ClientId!)
            ?? throw new InvalidOperationException(
                "The application cannot be found.");

        var identity = new ClaimsIdentity(
            authenticationType: Microsoft.IdentityModel.Tokens.TokenValidationParameters.DefaultAuthenticationType,
            nameType: Claims.Name,
            roleType: Claims.Role);

        identity.SetClaim(Claims.Subject,
            await ops.ApplicationManager.GetClientIdAsync(application) as string
                ?? request.ClientId!);
        identity.SetClaim(Claims.Name,
            await ops.ApplicationManager.GetDisplayNameAsync(application) as string
                ?? request.ClientId!);
        identity.SetScopes(request.GetScopes());
        identity.SetResources(await ops.ResolveResourcesAsync(identity, request));
        GrantOperations.ApplyDpopBinding(identity, proof);
        identity.SetDestinations(ops.GetDestinations);

        return new SignInResult(
            OpenIddictServerAspNetCoreDefaults.AuthenticationScheme,
            new ClaimsPrincipal(identity));
    }
}

/// <summary>
/// grant_type=password (legacy, default-off compatibility flag). CheckPasswordSignInAsync
/// enforces lockout; wrong-password, locked-out, not-allowed and unknown-user
/// all collapse into the SAME generic error (no enumeration).
/// </summary>
public sealed class PasswordGrantHandler : ITokenGrantHandler
{
    public IReadOnlyCollection<string> HandledGrantTypes { get; } =
        [GrantTypes.Password];

    public async Task<IActionResult> HandleAsync(TokenGrantContext context)
    {
        var (httpContext, request, proof, ops) =
            (context.HttpContext, context.Request, context.Proof, context.Operations);

        var user = await ops.UserManager.FindByNameAsync(request.Username!);

        var result = user is not null
            ? await ops.SignInManager.CheckPasswordSignInAsync(
                user, request.Password!, lockoutOnFailure: true)
            : Microsoft.AspNetCore.Identity.SignInResult.Failed;

        if (user is null || !result.Succeeded
            || !await ops.SignInManager.CanSignInAsync(user))
        {
            return TokenGrantDispatcher.ForbidError(Errors.InvalidGrant,
                "Invalid username or password.");
        }

        var identity = await ops.BuildIdentityAsync(
            user,
            GrantOperations.CreateAuthenticationContextPrincipal(
                ["pwd"],
                "urn:sufficit:acr:loa1"),
            httpContext.User);
        identity.SetScopes(request.GetScopes());
        identity.SetResources(await ops.ResolveResourcesAsync(identity, request));
        GrantOperations.ApplyDpopBinding(identity, proof);
        identity.SetDestinations(ops.GetDestinations);

        return new SignInResult(
            OpenIddictServerAspNetCoreDefaults.AuthenticationScheme,
            new ClaimsPrincipal(identity));
    }
}

/// <summary>
/// Config-driven gate for the RFC 8693 token-exchange grant (P0 #4/#8 —
/// eval finding "token exchange sem policy"). Bound from the
/// <c>Sufficit:Identity:TokenExchange</c> configuration section. Read via a
/// plain <see cref="Microsoft.Extensions.Configuration.IConfiguration"/>
/// injection in <see cref="GrantOperations"/> rather than being added
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
    /// Enforce rejects any subject token that cannot be attributed to exactly
    /// one authorized party (<c>azp</c>/<c>client_id</c>/presenter) and — when
    /// <see cref="AllowedClientIds"/> is configured — one whose party is not on
    /// that allow-list. Observe is retained only as an explicit posture-checked
    /// migration mode.
    /// </summary>
    /// <remarks>
    /// The unambiguous-party requirement applies with or without an allow-list
    /// (eval 2026-08-30, F-1). Until that change the entire check was skipped
    /// on the default empty allow-list, so the default deployment ran the
    /// exchange grant with no confused-deputy defense at all. A deployment
    /// whose subject tokens do not yet carry an unambiguous authorized party
    /// should set <c>Observe</c> for a bounded migration window; the production
    /// posture check reports that state.
    /// </remarks>
    public SecurityPolicyEnforcementMode ProvenanceMode { get; init; } =
        SecurityPolicyEnforcementMode.Enforce;
}

/// <summary>
/// RFC 8693 token exchange: subject-token provenance allowlist, delegated
/// scope/resource attenuation against the subject token, and the nested
/// <c>act</c> actor chain.
/// </summary>
public sealed class TokenExchangeGrantHandler(
    ISubjectTokenProvenancePolicy subjectTokenProvenancePolicy) : ITokenGrantHandler
{
    public IReadOnlyCollection<string> HandledGrantTypes { get; } =
        [GrantTypes.TokenExchange];

    public async Task<IActionResult> HandleAsync(TokenGrantContext context)
    {
        var (httpContext, request, proof, ops) =
            (context.HttpContext, context.Request, context.Proof, context.Operations);
        var tokenExchangeOptions = ops.TokenExchangeOptions;

        // Master kill switch + client allowlist, layered on TOP of the
        // OpenIddict-level Permissions.GrantTypes.TokenExchange the server
        // pipeline already enforces upstream.
        if (!tokenExchangeOptions.Enabled
            || (tokenExchangeOptions.AllowedClientIds.Count > 0
                && !tokenExchangeOptions.AllowedClientIds.Contains(request.ClientId!)))
        {
            return TokenGrantDispatcher.ForbidError(Errors.UnauthorizedClient,
                "This client is not allowed to perform token exchange.");
        }

        // The incoming subject_token has already been resolved and validated
        // by OpenIddict's own server handlers; its principal is retrieved
        // through the ASP.NET Core authentication handler.
        var result = await httpContext.AuthenticateAsync(
            OpenIddictServerAspNetCoreDefaults.AuthenticationScheme);
        if (result is not { Succeeded: true, Principal: not null })
        {
            return TokenGrantDispatcher.ForbidError(Errors.InvalidGrant,
                "The subject_token is missing, invalid or expired.");
        }

        var subject = result.Principal.GetClaim(Claims.Subject);
        var user = subject is not null
            ? await ops.UserManager.FindByIdAsync(subject)
            : null;

        if (user is null || !await ops.SignInManager.CanSignInAsync(user))
        {
            return TokenGrantDispatcher.ForbidError(Errors.InvalidGrant,
                "The subject_token no longer identifies a user that is allowed to sign in.");
        }

        // Confused-deputy defense (RFC 8693 §4.1 / RFC 8707). This runs for
        // EVERY exchange, not only when AllowedClientIds is configured
        // (eval 2026-08-30, F-1): the previous gate meant the default
        // deployment — empty allow-list — performed no provenance check at
        // all, so any client holding the token-exchange grant permission could
        // present a subject token minted for a different relying party. The
        // policy always requires an unambiguous authorized party and, when an
        // allow-list exists, that the party belongs to it. Observe mode remains
        // the explicit, posture-checked migration escape hatch.
        var provenance = subjectTokenProvenancePolicy.Evaluate(
            result.Principal,
            tokenExchangeOptions.AllowedClientIds,
            tokenExchangeOptions.ProvenanceMode,
            request.ClientId);
        if (provenance.ShouldReject)
        {
            return TokenGrantDispatcher.ForbidError(Errors.InvalidGrant,
                "The subject_token was not issued for this client, so it cannot be exchanged by it.");
        }

        var identity = await ops.BuildIdentityAsync(
            user, result.Principal, httpContext.User);

        // Delegated scopes are the intersection of what the calling client
        // asked for and what the subject_token itself carried; a client that
        // doesn't request any scope inherits the subject's full scope set.
        var requestedScopes = request.GetScopes();
        var subjectScopes = result.Principal.GetScopes();
        identity.SetScopes(requestedScopes.Length > 0
            ? requestedScopes.Intersect(subjectScopes)
            : (IEnumerable<string>)subjectScopes);

        var delegatedResources = (await ops.ResolveResourcesAsync(identity, request))
            .ToHashSet(StringComparer.Ordinal);
        var subjectResources = result.Principal.GetResources()
            .Concat(result.Principal.GetAudiences())
            .ToHashSet(StringComparer.Ordinal);
        var requestedResources = request.GetResources();
        if (requestedResources.Any(resource => !subjectResources.Contains(resource)))
        {
            return TokenGrantDispatcher.ForbidError(Errors.InvalidTarget,
                "The requested resource is not authorized by the subject_token.");
        }
        identity.SetResources(delegatedResources.Intersect(subjectResources));

        // RFC 8693 §4.1: identify the acting party, NESTING any actor chain
        // the subject_token already carried instead of overwriting it.
        var priorAct = result.Principal.GetClaim(GrantOperations.ActClaimType);
        object actClaim = priorAct is not null
            ? new { sub = request.ClientId, act = JsonSerializer.Deserialize<JsonElement>(priorAct) }
            : new { sub = request.ClientId };
        identity.SetClaim(GrantOperations.ActClaimType,
            JsonSerializer.SerializeToElement(actClaim));

        GrantOperations.ApplyDpopBinding(identity, proof);
        identity.SetDestinations(ops.GetDestinations);

        return new SignInResult(
            OpenIddictServerAspNetCoreDefaults.AuthenticationScheme,
            new ClaimsPrincipal(identity));
    }
}
