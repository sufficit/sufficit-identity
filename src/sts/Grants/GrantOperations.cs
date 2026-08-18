using System.Collections.Immutable;
using System.Security.Claims;
using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.Configuration;
using OpenIddict.Abstractions;
using static OpenIddict.Abstractions.OpenIddictConstants;
using Sufficit.Identity.Core.Entities;

namespace Sufficit.Identity.STS.Grants;

/// <summary>
/// Shared building blocks for every token-endpoint grant (A2, eval
/// 2026-08-14): principal construction from current user state, scope and
/// resource resolution, claim destinations, and DPoP binding. Previously
/// private members of <c>AuthorizationController</c> — moved verbatim so each
/// <see cref="ITokenGrantHandler"/> composes the same pipeline, and future
/// grants (RFC 7523 assertions, CIMD) plug in without touching the controller.
/// </summary>
public sealed class GrantOperations(
    UserManager<ApplicationUser> userManager,
    SignInManager<ApplicationUser> signInManager,
    IOpenIddictApplicationManager applicationManager,
    IOpenIddictScopeManager scopeManager,
    IApplicationClaimDestinationPolicy applicationClaimPolicy,
    IAuthenticationContextProjector authenticationContextProjector,
    ScopeEntitlementProvisioner scopeEntitlementProvisioner,
    IConfiguration configuration)
{
    internal const string SessionIdClaimType =
        OidcSessionClaimsPrincipalFactory.SessionIdClaimType;

    // `address` is an OIDC structured claim. Legacy user claims may use the
    // same name for arbitrary text, so preserve those values under Sufficit's
    // private namespace instead of asking the Identity service to understand
    // domain-specific address data.
    internal const string LegacyAddressClaimType = "urn:sufficit:claim:address";

    internal const string ActClaimType = "act";

    public UserManager<ApplicationUser> UserManager => userManager;
    public SignInManager<ApplicationUser> SignInManager => signInManager;
    public IOpenIddictApplicationManager ApplicationManager => applicationManager;
    public IOpenIddictScopeManager ScopeManager => scopeManager;
    public IApplicationClaimDestinationPolicy ApplicationClaimPolicy => applicationClaimPolicy;

    public Task<IdentityResult> ProvisionScopeEntitlementsAsync(
        ApplicationUser user,
        IEnumerable<string> approvedScopes,
        CancellationToken cancellationToken = default) =>
        scopeEntitlementProvisioner.ProvisionAsync(
            user,
            approvedScopes,
            cancellationToken);

    public TokenExchangeOptions TokenExchangeOptions { get; } =
        configuration.GetSection("Sufficit:Identity:TokenExchange")
            .Get<TokenExchangeOptions>() ?? new TokenExchangeOptions();

    /// <summary>
    /// Attaches the DPoP confirmation handoff claim (<c>sufficit_private_dpop_jkt</c>)
    /// when the request carried a valid DPoP proof (RFC 9449 §7.2). OpenIddict
    /// strips inherited <c>cnf</c> claims while preparing token principals, so the
    /// thumbprint travels in a non-emitted marker and the custom ProcessSignIn
    /// handler attaches <c>cnf</c> after that preparation stage. No-op when the
    /// proof was absent/invalid (and not required).
    /// </summary>
    public static void ApplyDpopBinding(
        ClaimsIdentity identity,
        Dpop.DpopProof? proof)
    {
        if (proof is null) return;
        identity.SetClaim(
            Dpop.DpopProofValidator.BindingThumbprintClaimType,
            proof.KeyThumbprint);
    }

    public static bool HasMatchingDpopBinding(
        ClaimsPrincipal principal,
        Dpop.DpopProof? proof)
    {
        var boundThumbprint = principal.GetClaim(
            Dpop.DpopProofValidator.BindingThumbprintClaimType);
        if (string.IsNullOrEmpty(boundThumbprint)) return true;
        if (proof is null) return false;
        return string.Equals(
            boundThumbprint,
            proof.KeyThumbprint,
            StringComparison.Ordinal);
    }

    /// <summary>
    /// Best-effort extraction of the <c>nonce</c> claim from a DPoP proof
    /// header, without full validation. The value is accepted only after the
    /// partition-bound nonce protector and full proof validator approve it.
    /// </summary>
    public static string? ExtractNonceFromHeader(string? dpopHeader)
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

    public static ClaimsPrincipal CreateAuthenticationContextPrincipal(
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

    public async Task<ClaimsIdentity> BuildIdentityAsync(
        ApplicationUser user,
        ClaimsPrincipal? authenticationContext = null,
        ClaimsPrincipal? hostPrincipal = null)
    {
        var identity = new ClaimsIdentity(
            authenticationType: Microsoft.IdentityModel.Tokens.TokenValidationParameters.DefaultAuthenticationType,
            nameType: Claims.Name,
            roleType: Claims.Role);

        identity.SetClaim(Claims.Subject, await userManager.GetUserIdAsync(user))
                .SetClaim(Claims.Email, await userManager.GetEmailAsync(user))
                .SetClaim(Claims.Name, await userManager.GetUserNameAsync(user))
                .SetClaim(Claims.PreferredUsername, await userManager.GetUserNameAsync(user))
                .SetClaims(Claims.Role, [.. await userManager.GetRolesAsync(user)]);

        var sessionId = hostPrincipal?.GetClaim(SessionIdClaimType);
        if (!string.IsNullOrWhiteSpace(sessionId))
        {
            identity.SetClaim(SessionIdClaimType, sessionId);
        }

        authenticationContextProjector.Project(
            authenticationContext ?? hostPrincipal ?? new ClaimsPrincipal(),
            identity);

        // Project persisted claims (AspNetUserClaims — e.g. `directive`,
        // required by downstream APIs for authorization) onto the token.
        // Without this, the 5000+ claims stored against users never reach
        // any token.
        await AddPersistedClaimsAsync(identity, user);

        return identity;
    }

    /// <summary>
    /// Claim types already derived from ASP.NET Core Identity in
    /// <see cref="BuildIdentityAsync"/>. Persisted claims of these types are
    /// skipped when re-projecting the user's stored claims, and the OIDC
    /// <c>address</c> claim is remapped to Sufficit's private namespace
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

    /// <summary>
    /// Copies the user's persisted claims (AspNetUserClaims) onto the identity,
    /// skipping reserved types and exact duplicates, preserving multiple
    /// distinct values per type.
    /// </summary>
    public async Task AddPersistedClaimsAsync(ClaimsIdentity identity, ApplicationUser user)
    {
        var existing = new HashSet<(string Type, string Value)>(
            identity.Claims.Select(claim => (claim.Type, claim.Value)));

        foreach (var claim in await userManager.GetClaimsAsync(user))
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
    /// (a) resources derived from the granted scopes and (b) any
    /// <c>resource</c> indicators the client explicitly requested (RFC 8707).
    /// OpenIddict validates the requested resource against the client's
    /// <c>oi_rprm</c> permission BEFORE this runs.
    /// </summary>
    public async Task<List<string>> ResolveResourcesAsync(
        ClaimsIdentity identity,
        OpenIddictRequest? request)
    {
        var resources = new List<string>();
        await foreach (var resource in scopeManager.ListResourcesAsync(identity.GetScopes()))
        {
            resources.Add(resource);
        }
        if (request is not null)
        {
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
    /// Gates which token(s) each claim reaches: name/email/role are bound to
    /// their matching scope for BOTH tokens; authentication-context claims
    /// travel to both; sid is ID-token-only; DPoP confirmation is
    /// access-token-only; custom persisted claims follow the config-driven
    /// <see cref="IApplicationClaimDestinationPolicy"/>.
    /// </summary>
    public IEnumerable<string> GetDestinations(Claim claim)
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
                // DPoP confirmation (RFC 9449 §7.2): route to the access
                // token only — resource servers validate it; the id_token is
                // for the client and must not carry the sender-binding
                // thumbprint.
                yield return Destinations.AccessToken;
                yield break;

            case Dpop.DpopProofValidator.BindingThumbprintClaimType:
                // Internal handoff consumed by AttachDpopConfirmation after
                // OpenIddict prepares the concrete token principals.
                yield break;

            default:
                // Custom persisted claims (AspNetUserClaims): the
                // config-driven claim-to-scope map decides (eval #10).
                foreach (var destination in applicationClaimPolicy.GetDestinations(
                             claim, includeIdentityToken: true))
                    yield return destination;
                break;
        }
    }

    /// <summary>
    /// Materializes an <see cref="IAsyncEnumerable{T}"/> into a list (the
    /// OpenIddict managers expose results as async streams).
    /// </summary>
    public static async Task<List<T>> ToListAsync<T>(IAsyncEnumerable<T> source)
    {
        var list = new List<T>();
        await foreach (var item in source)
        {
            list.Add(item);
        }
        return list;
    }
}
