using System.Security.Claims;
using OpenIddict.Abstractions;
using OpenIddict.Server;
using static OpenIddict.Server.OpenIddictServerEvents;
using static OpenIddict.Abstractions.OpenIddictConstants;
using Sufficit.Identity.Application.Security;

namespace Sufficit.Identity.STS;

/// <summary>
/// Default <see cref="IPrivilegedTokenMintingService"/>: the ONE place where
/// reference access tokens are minted outside the grant pipeline (A3, eval
/// 2026-08-14). Owns the OpenIddict dispatch contract (transaction,
/// GenerateTokenContext with reference + persisted payload, rejection
/// handling), issuer resolution and the uniform identity scaffolding
/// (public scope claim, private issuer/creation/expiration metadata,
/// resources-from-scopes, access-token-only destinations by default).
/// Issuance POLICY stays with the callers.
/// </summary>
public sealed class PrivilegedTokenMintingService(
    IOpenIddictServerDispatcher dispatcher,
    IOpenIddictServerFactory factory,
    IOpenIddictScopeManager scopeManager) : IPrivilegedTokenMintingService
{
    public async Task<PrivilegedTokenMint> MintAsync(
        PrivilegedTokenMintRequest request,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(request);

        var identity = new ClaimsIdentity(
            authenticationType: request.AuthenticationType,
            nameType: Claims.Name,
            roleType: Claims.Role);

        identity.SetClaim(Claims.Subject, request.Subject);
        identity.SetClaim(Claims.ClientId, request.ClientId);
        identity.SetClaim(Claims.Name,
            request.DisplayName ?? request.Subject);
        identity.SetClaim(Claims.Scope, string.Join(' ', request.Scopes));
        identity.SetScopes(request.Scopes);
        identity.SetCreationDate(request.CreatedAtUtc);
        identity.SetExpirationDate(request.ExpiresAtUtc);
        if (string.IsNullOrWhiteSpace(request.Issuer))
        {
            throw new InvalidOperationException(
                "A privileged token cannot be minted without a configured issuer.");
        }
        identity.SetClaim(Claims.Private.Issuer, request.Issuer);

        foreach (var (type, value) in request.StringClaims)
        {
            identity.SetClaim(type, value);
        }

        foreach (var claim in request.EvidenceClaims)
        {
            identity.AddClaim(new Claim(claim.Type, claim.Value));
        }

        // Resources: resolve from the granted scopes unless the caller
        // decided them; materialize both the private audience metadata (so
        // introspection identifies the resource servers) and the public
        // audience claim.
        var resources = request.Resources;
        if (resources is null)
        {
            var resolved = new List<string>();
            await foreach (var resource in scopeManager.ListResourcesAsync(
                               identity.GetScopes(), cancellationToken))
            {
                resolved.Add(resource);
            }
            resources = resolved;
        }
        identity.SetResources(resources);
        identity.SetClaims(Claims.Audience, [.. resources]);

        // Bearer references: every claim reaches the access token only.
        identity.SetDestinations(
            request.Destinations ?? (_ => [Destinations.AccessToken]));

        return await MintPrincipalAsync(
            new ClaimsPrincipal(identity),
            createEntry: true,
            referenceToken: true,
            persistPayload: true,
            cancellationToken);
    }

    public async Task<PrivilegedTokenMint> MintPrincipalAsync(
        ClaimsPrincipal principal,
        bool createEntry = true,
        bool referenceToken = true,
        bool persistPayload = true,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(principal);

        var transaction = await factory.CreateTransactionAsync();
        var context = new GenerateTokenContext(transaction)
        {
            CreateTokenEntry = createEntry,
            IsReferenceToken = referenceToken,
            PersistTokenPayload = persistPayload,
            Principal = principal,
            TokenFormat = TokenFormats.Private.JsonWebToken,
            TokenType = TokenTypeIdentifiers.AccessToken,
        };

        await dispatcher.DispatchAsync(context);
        if (context.IsRejected
            || string.IsNullOrWhiteSpace(context.Token)
            || string.IsNullOrWhiteSpace(context.Principal?.GetTokenId()))
        {
            throw new InvalidOperationException(
                context.ErrorDescription
                ?? "OpenIddict could not mint the privileged token.");
        }

        return new PrivilegedTokenMint(
            context.Principal!.GetTokenId()!,
            context.Token,
            principal.GetCreationDate()
                ?? DateTimeOffset.UtcNow,
            principal.GetExpirationDate()
                ?? DateTimeOffset.UtcNow.AddMinutes(5));
    }

}
