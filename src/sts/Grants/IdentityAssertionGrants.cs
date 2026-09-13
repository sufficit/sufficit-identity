using System.Security.Claims;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Tokens;
using OpenIddict.Abstractions;
using OpenIddict.Server;
using OpenIddict.Server.AspNetCore;
using static OpenIddict.Abstractions.OpenIddictConstants;

namespace Sufficit.Identity.STS.Grants;

/// <summary>
/// Identity Assertion JWT Authorization Grant (ID-JAG,
/// draft-ietf-oauth-identity-assertion-authz-grant-04) identifiers.
/// </summary>
public static class IdentityAssertionGrant
{
    public const string TokenType = "urn:ietf:params:oauth:token-type:id-jag";

    public const string JwtType = "oauth-id-jag+jwt";

    public const string GrantProfile = "urn:ietf:params:oauth:grant-profile:id-jag";

    public const string JwtBearerGrantType = "urn:ietf:params:oauth:grant-type:jwt-bearer";

    /// <summary>
    /// The issuer identifier as OpenIddict publishes it: the configured
    /// issuer, or the request base URI when none is configured.
    /// </summary>
    public static string ResolveIssuer(HttpContext httpContext, SufficitIdentityOptions options)
    {
        if (!string.IsNullOrWhiteSpace(options.Issuer))
        {
            return new Uri(options.Issuer, UriKind.Absolute).AbsoluteUri;
        }

        var request = httpContext.Request;
        return new Uri(
            $"{request.Scheme}://{request.Host}{request.PathBase}/",
            UriKind.Absolute).AbsoluteUri;
    }
}

/// <summary>
/// Signs ID-JAGs with the STS signing key, so a resource authorization server
/// validates them against the published JWKS.
/// </summary>
public sealed class IdentityAssertionSigner(SigningCredentials signingCredentials)
{
    private readonly JsonWebTokenHandler _handler = new();

    public string Sign(
        IDictionary<string, object> claims,
        DateTimeOffset issuedAt,
        DateTimeOffset expires) =>
        _handler.CreateToken(new SecurityTokenDescriptor
        {
            Claims = claims,
            IssuedAt = issuedAt.UtcDateTime,
            NotBefore = issuedAt.UtcDateTime,
            Expires = expires.UtcDateTime,
            SigningCredentials = signingCredentials,
            TokenType = IdentityAssertionGrant.JwtType,
        });
}

/// <summary>
/// IdP role (§4.3): issues an ID-JAG in exchange for an ID Token or refresh
/// token the calling client holds for a user.
/// </summary>
/// <remarks>
/// The general token-exchange provenance and delegation rules do not apply:
/// the grant is not a delegated access token but an identity assertion
/// addressed to another authorization server. The draft's own binding rules
/// replace them — the subject token must have been issued to the caller, the
/// audience must be a configured trust relationship, and the user must still
/// be allowed to sign in. actor_token processing is outside the draft's scope
/// and is ignored; authorization_details is not supported and is rejected.
/// </remarks>
public sealed class IdentityAssertionIssuer(
    SufficitIdentityOptions options,
    IdentityAssertionSigner signer,
    TimeProvider timeProvider)
{
    public async Task<IActionResult> IssueAsync(
        TokenGrantContext context,
        ClaimsPrincipal subjectToken)
    {
        var (httpContext, request, ops) =
            (context.HttpContext, context.Request, context.Operations);
        var issuance = options.IdentityAssertions.Issuance;
        var clientId = request.ClientId!;

        if (!issuance.Enabled)
        {
            return TokenGrantDispatcher.ForbidError(Errors.InvalidRequest,
                "Identity assertion grants are not issued by this server.");
        }

        var isIdentityToken = string.Equals(request.SubjectTokenType,
            TokenTypeIdentifiers.IdentityToken, StringComparison.Ordinal);
        var isRefreshToken = string.Equals(request.SubjectTokenType,
            TokenTypeIdentifiers.RefreshToken, StringComparison.Ordinal);
        if (!isIdentityToken && !isRefreshToken)
        {
            return TokenGrantDispatcher.ForbidError(Errors.InvalidRequest,
                "An identity assertion grant requires an id_token or refresh_token subject_token.");
        }

        if (request.HasParameter("authorization_details"))
        {
            return TokenGrantDispatcher.ForbidError(Errors.InvalidRequest,
                "authorization_details is not supported for identity assertion grants.");
        }

        var requestedAudiences = request.GetAudiences();
        if (requestedAudiences.Length != 1)
        {
            return TokenGrantDispatcher.ForbidError(Errors.InvalidRequest,
                "Exactly one audience is required.");
        }

        var target = issuance.Audiences.FirstOrDefault(audience =>
            string.Equals(audience.Issuer, requestedAudiences[0], StringComparison.Ordinal)
            || audience.Aliases.Contains(requestedAudiences[0], StringComparer.Ordinal));
        if (target is null || string.IsNullOrWhiteSpace(target.Issuer))
        {
            return TokenGrantDispatcher.ForbidError(Errors.InvalidTarget,
                "The audience is not a trusted authorization server.");
        }

        if (target.AllowedClientIds.Length > 0
            && !target.AllowedClientIds.Contains(clientId, StringComparer.Ordinal))
        {
            return TokenGrantDispatcher.ForbidError(Errors.UnauthorizedClient,
                "This client may not request identity assertion grants for the audience.");
        }

        // §4.3.3: an identity assertion must be addressed to the caller; a
        // refresh token must be bound to it.
        var issuedToCaller = isIdentityToken
            ? subjectToken.GetAudiences().Contains(clientId, StringComparer.Ordinal)
            : subjectToken.GetPresenters().Contains(clientId, StringComparer.Ordinal)
                || string.Equals(subjectToken.GetClaim(Claims.AuthorizedParty), clientId, StringComparison.Ordinal)
                || string.Equals(subjectToken.GetClaim(Claims.ClientId), clientId, StringComparison.Ordinal);
        if (!issuedToCaller)
        {
            return TokenGrantDispatcher.ForbidError(Errors.InvalidGrant,
                "The subject_token was not issued to this client.");
        }

        var subject = subjectToken.GetClaim(Claims.Subject);
        var user = subject is not null
            ? await ops.UserManager.FindByIdAsync(subject)
            : null;
        if (user is null || !await ops.SignInManager.CanSignInAsync(user))
        {
            return TokenGrantDispatcher.ForbidError(Errors.InvalidGrant,
                "The subject_token no longer identifies a user that is allowed to sign in.");
        }

        // Scopes and resources name the other authorization server's catalog;
        // DeferIdentityAssertionRequestValidation kept them away from the local
        // scope and resource validation.
        var requestedScopes = ((string?)request.GetParameter(
                DeferIdentityAssertionRequestValidation.ScopeParameter) ?? string.Empty)
            .Split(' ', StringSplitOptions.RemoveEmptyEntries);
        var grantedScopes = (target.AllowedScopes.Length > 0
                ? requestedScopes.Intersect(target.AllowedScopes, StringComparer.Ordinal)
                : requestedScopes)
            .Distinct(StringComparer.Ordinal)
            .ToArray();
        if (requestedScopes.Length > 0 && grantedScopes.Length == 0)
        {
            return TokenGrantDispatcher.ForbidError(Errors.InvalidScope,
                "None of the requested scopes may be granted for the audience.");
        }

        var requestedResources = ((string?)request.GetParameter(
                DeferIdentityAssertionRequestValidation.ResourceParameter) ?? string.Empty)
            .Split(' ', StringSplitOptions.RemoveEmptyEntries);
        if (requestedResources.Any(resource =>
            !Uri.TryCreate(resource, UriKind.Absolute, out var uri) || !string.IsNullOrEmpty(uri.Fragment)))
        {
            return TokenGrantDispatcher.ForbidError(Errors.InvalidTarget,
                "Each resource must be an absolute URI without a fragment.");
        }

        var grantedResources = (target.AllowedResources.Length > 0
                ? requestedResources.Intersect(target.AllowedResources, StringComparer.Ordinal)
                : requestedResources)
            .Distinct(StringComparer.Ordinal)
            .ToArray();
        if (requestedResources.Length > 0 && grantedResources.Length == 0)
        {
            return TokenGrantDispatcher.ForbidError(Errors.InvalidTarget,
                "None of the requested resources may be granted for the audience.");
        }

        var now = timeProvider.GetUtcNow();
        var lifetime = TimeSpan.FromSeconds(Math.Clamp(issuance.LifetimeSeconds, 60, 3600));
        var claims = new Dictionary<string, object>(StringComparer.Ordinal)
        {
            [JwtRegisteredClaimNames.Iss] = IdentityAssertionGrant.ResolveIssuer(httpContext, options),
            [JwtRegisteredClaimNames.Sub] = await ops.UserManager.GetUserIdAsync(user),
            [JwtRegisteredClaimNames.Aud] = target.Issuer,
            [Claims.ClientId] = target.ClientIdMap.TryGetValue(clientId, out var remoteClientId)
                && !string.IsNullOrWhiteSpace(remoteClientId)
                    ? remoteClientId
                    : clientId,
            [JwtRegisteredClaimNames.Jti] = Guid.NewGuid().ToString("N"),
        };

        if (grantedScopes.Length > 0)
        {
            claims[Claims.Scope] = string.Join(' ', grantedScopes);
        }

        if (grantedResources.Length == 1)
        {
            claims["resource"] = grantedResources[0];
        }
        else if (grantedResources.Length > 1)
        {
            claims["resource"] = grantedResources;
        }

        if (long.TryParse(subjectToken.GetClaim(Claims.AuthenticationTime), out var authTime))
        {
            claims[Claims.AuthenticationTime] = authTime;
        }

        var authenticationContextClass = subjectToken.GetClaim(Claims.AuthenticationContextReference);
        if (!string.IsNullOrWhiteSpace(authenticationContextClass))
        {
            claims[Claims.AuthenticationContextReference] = authenticationContextClass;
        }

        var methods = subjectToken.GetClaims(Claims.AuthenticationMethodReference);
        if (methods.Length > 0)
        {
            claims[Claims.AuthenticationMethodReference] = methods.ToArray();
        }

        if (issuance.IncludeEmail && user.EmailConfirmed && !string.IsNullOrWhiteSpace(user.Email))
        {
            claims[Claims.Email] = user.Email;
        }

        if (context.Proof is not null)
        {
            claims[Dpop.DpopProofValidator.ConfirmationClaimType] = new Dictionary<string, object>
            {
                [Dpop.DpopProofValidator.JktClaimMember] = context.Proof.KeyThumbprint,
            };
        }

        var grant = signer.Sign(claims, now, now.Add(lifetime));

        httpContext.Response.Headers.CacheControl = "no-store";
        httpContext.Response.Headers.Pragma = "no-cache";
        var response = new Dictionary<string, object>(StringComparer.Ordinal)
        {
            [Parameters.IssuedTokenType] = IdentityAssertionGrant.TokenType,
            [Parameters.AccessToken] = grant,
            [Parameters.TokenType] = "N_A",
            [Parameters.ExpiresIn] = (long)lifetime.TotalSeconds,
        };
        if (grantedScopes.Length > 0)
        {
            response[Parameters.Scope] = string.Join(' ', grantedScopes);
        }

        return new JsonResult(response);
    }
}

/// <summary>
/// Moves the scope and resource parameters of an ID-JAG token-exchange request
/// out of OpenIddict's local validation, which rejects values that are not
/// registered here. Those values belong to the receiving authorization server,
/// so registering them locally would also publish them in this server's
/// discovery document. The issuer applies the per-audience allow-lists instead.
/// </summary>
/// <remarks>
/// The reserved parameters are removed from every token request first, so a
/// client cannot supply them directly.
/// </remarks>
public sealed class DeferIdentityAssertionRequestValidation
    : IOpenIddictServerHandler<OpenIddictServerEvents.ValidateTokenRequestContext>
{
    public const string ScopeParameter = ".identity_assertion_scope";

    public const string ResourceParameter = ".identity_assertion_resource";

    public static OpenIddictServerHandlerDescriptor Descriptor { get; } =
        OpenIddictServerHandlerDescriptor
            .CreateBuilder<OpenIddictServerEvents.ValidateTokenRequestContext>()
            .UseSingletonHandler<DeferIdentityAssertionRequestValidation>()
            .SetOrder(int.MinValue + 50_000)
            .SetType(OpenIddictServerHandlerType.Custom)
            .Build();

    public ValueTask HandleAsync(OpenIddictServerEvents.ValidateTokenRequestContext context)
    {
        var request = context.Request;
        request.RemoveParameter(ScopeParameter);
        request.RemoveParameter(ResourceParameter);

        if (!request.IsTokenExchangeGrantType()
            || !string.Equals(request.RequestedTokenType,
                IdentityAssertionGrant.TokenType, StringComparison.Ordinal))
        {
            return ValueTask.CompletedTask;
        }

        if (!string.IsNullOrEmpty(request.Scope))
        {
            request.SetParameter(ScopeParameter, request.Scope);
            request.Scope = null;
        }

        var resources = request.GetResources();
        if (resources.Length > 0)
        {
            // Resource indicators are absolute URIs, which cannot contain spaces.
            request.SetParameter(ResourceParameter, string.Join(' ', resources));
            request.Resources = null;
        }

        return ValueTask.CompletedTask;
    }
}

/// <summary>Resolves the signing keys of a trusted ID-JAG issuer.</summary>
public interface IIdentityAssertionKeyResolver
{
    Task<IReadOnlyList<SecurityKey>> GetSigningKeysAsync(
        IdentityAssertionTrustedIssuer issuer,
        string? keyId,
        CancellationToken cancellationToken);
}

/// <summary>
/// Resource authorization server role (§4.4): redeems an ID-JAG presented
/// with the RFC 7523 jwt-bearer grant for a local access token.
/// </summary>
/// <remarks>
/// The subject resolves only through an existing external login for the
/// trusted issuer, never by email, so an identity provider cannot assert an
/// arbitrary local account. Authentication methods asserted by the foreign
/// issuer are not projected into the local token: step-up decisions stay with
/// the local authentication context. No refresh token is issued (§4.4.3).
/// </remarks>
public sealed class IdentityAssertionGrantHandler(
    SufficitIdentityOptions options,
    IIdentityAssertionKeyResolver keyResolver) : ITokenGrantHandler
{
    private static readonly JsonWebTokenHandler TokenHandler = new();

    public IReadOnlyCollection<string> HandledGrantTypes { get; } =
        [IdentityAssertionGrant.JwtBearerGrantType];

    public async Task<IActionResult> HandleAsync(TokenGrantContext context)
    {
        var (httpContext, request, proof, ops) =
            (context.HttpContext, context.Request, context.Proof, context.Operations);
        var redemption = options.IdentityAssertions.Redemption;
        var clientId = request.ClientId;

        if (!redemption.Enabled)
        {
            return TokenGrantDispatcher.ForbidError(Errors.UnsupportedGrantType, null);
        }

        if (string.IsNullOrWhiteSpace(request.Assertion) || string.IsNullOrWhiteSpace(clientId))
        {
            return TokenGrantDispatcher.ForbidError(Errors.InvalidRequest,
                "The assertion parameter and client authentication are required.");
        }

        var application = await ops.ApplicationManager.FindByClientIdAsync(clientId);
        if (application is null
            || !await ops.ApplicationManager.HasClientTypeAsync(application, ClientTypes.Confidential))
        {
            return TokenGrantDispatcher.ForbidError(Errors.UnauthorizedClient,
                "Identity assertion grants can only be redeemed by a confidential client.");
        }

        JsonWebToken assertion;
        try
        {
            assertion = new JsonWebToken(request.Assertion);
        }
        catch (ArgumentException)
        {
            return InvalidGrant("The assertion is not a well-formed JWT.");
        }

        var trusted = redemption.TrustedIssuers.FirstOrDefault(issuer =>
            !string.IsNullOrWhiteSpace(issuer.Issuer)
            && string.Equals(issuer.Issuer, assertion.Issuer, StringComparison.Ordinal));
        if (trusted is null || string.IsNullOrWhiteSpace(trusted.LoginProvider))
        {
            return InvalidGrant("The assertion was not issued by a trusted identity provider.");
        }

        if (trusted.AllowedClientIds.Length > 0
            && !trusted.AllowedClientIds.Contains(clientId, StringComparer.Ordinal))
        {
            return TokenGrantDispatcher.ForbidError(Errors.UnauthorizedClient,
                "This client may not redeem identity assertion grants from the issuer.");
        }

        if (!string.Equals(assertion.Typ, IdentityAssertionGrant.JwtType, StringComparison.OrdinalIgnoreCase))
        {
            return InvalidGrant("The assertion is not an identity assertion JWT authorization grant.");
        }

        // §4.4.1: aud is a string or a single-element array holding exactly
        // this server's issuer identifier.
        var issuer = IdentityAssertionGrant.ResolveIssuer(httpContext, options);
        var audiences = assertion.Audiences.ToArray();
        if (audiences.Length != 1 || !string.Equals(audiences[0], issuer, StringComparison.Ordinal))
        {
            return InvalidGrant("The assertion audience is not this authorization server.");
        }

        if (!assertion.TryGetPayloadValue<string>(Claims.ClientId, out var assertedClientId)
            || !string.Equals(assertedClientId, clientId, StringComparison.Ordinal))
        {
            return InvalidGrant("The assertion was not issued for this client.");
        }

        IReadOnlyList<SecurityKey> keys;
        try
        {
            keys = await keyResolver.GetSigningKeysAsync(
                trusted, assertion.Kid, httpContext.RequestAborted);
        }
        catch (Exception exception) when (exception is HttpRequestException
            or InvalidOperationException or TaskCanceledException)
        {
            return InvalidGrant("The identity provider's signing keys could not be resolved.");
        }

        var validation = await TokenHandler.ValidateTokenAsync(request.Assertion,
            new TokenValidationParameters
            {
                ValidIssuer = trusted.Issuer,
                ValidAudience = issuer,
                IssuerSigningKeys = keys,
                ValidTypes = [IdentityAssertionGrant.JwtType],
                RequireSignedTokens = true,
                RequireExpirationTime = true,
                ValidateLifetime = true,
                ClockSkew = TimeSpan.FromSeconds(30),
            });
        if (!validation.IsValid)
        {
            return InvalidGrant("The assertion signature or lifetime is invalid.");
        }

        if (assertion.IssuedAt == DateTime.MinValue
            || string.IsNullOrWhiteSpace(assertion.Id)
            || (assertion.ValidTo - assertion.IssuedAt).TotalSeconds
                > Math.Max(60, redemption.MaxAssertionLifetimeSeconds))
        {
            return InvalidGrant("The assertion must carry jti and iat and have a bounded lifetime.");
        }

        var user = string.IsNullOrWhiteSpace(assertion.Subject)
            ? null
            : await ops.UserManager.FindByLoginAsync(trusted.LoginProvider, assertion.Subject);
        if (user is null || !await ops.SignInManager.CanSignInAsync(user))
        {
            return InvalidGrant("The assertion subject is not linked to a local account that is allowed to sign in.");
        }

        var assertedScopes = assertion.TryGetPayloadValue<string>(Claims.Scope, out var scopeValue)
            ? scopeValue.Split(' ', StringSplitOptions.RemoveEmptyEntries)
            : [];
        var grantedScopes = new List<string>();
        foreach (var scope in assertedScopes.Distinct(StringComparer.Ordinal))
        {
            if (string.Equals(scope, Scopes.OfflineAccess, StringComparison.Ordinal)
                || (trusted.AllowedScopes.Length > 0
                    && !trusted.AllowedScopes.Contains(scope, StringComparer.Ordinal))
                || !await ops.ApplicationManager.HasPermissionAsync(
                    application, Permissions.Prefixes.Scope + scope))
            {
                continue;
            }

            grantedScopes.Add(scope);
        }

        if (assertedScopes.Length > 0 && grantedScopes.Count == 0)
        {
            return TokenGrantDispatcher.ForbidError(Errors.InvalidScope,
                "None of the asserted scopes may be granted to this client.");
        }

        var identity = await ops.BuildIdentityAsync(user);
        identity.SetScopes(grantedScopes);

        var resources = await ops.ResolveResourcesAsync(identity, request: null);
        var assertedResources = assertion.Claims
            .Where(claim => claim.Type == "resource")
            .Select(claim => claim.Value)
            .ToHashSet(StringComparer.Ordinal);
        if (assertedResources.Count > 0)
        {
            resources = resources.Where(assertedResources.Contains).ToList();
            if (resources.Count == 0)
            {
                return TokenGrantDispatcher.ForbidError(Errors.InvalidTarget,
                    "None of the asserted resources is served for the granted scopes.");
            }
        }

        identity.SetResources(resources);
        GrantOperations.ApplyDpopBinding(identity, proof);
        identity.SetDestinations(ops.GetDestinations);

        return new Microsoft.AspNetCore.Mvc.SignInResult(
            OpenIddictServerAspNetCoreDefaults.AuthenticationScheme,
            new ClaimsPrincipal(identity));
    }

    private static ForbidResult InvalidGrant(string description) =>
        TokenGrantDispatcher.ForbidError(Errors.InvalidGrant, description);
}
