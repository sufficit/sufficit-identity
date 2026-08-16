using Microsoft.Extensions.Logging;
using OpenIddict.Abstractions;
using static OpenIddict.Abstractions.OpenIddictConstants;

namespace Sufficit.Identity.STS.Cimd;

/// <summary>
/// Provisions OpenIddict applications from Client ID Metadata Documents on
/// first use (A10, eval 2026-08-14): when an authorization request arrives
/// with an unknown client_id that has the CIMD URL shape, the document is
/// fetched, validated (<see cref="ClientIdMetadataResolver"/>) and a
/// public, PKCE-required, explicit-consent client row is created — the same
/// secure defaults every other dynamically provisioned client is born with.
/// </summary>
/// <remarks>
/// <para>
/// Scope of this first implementation: public clients with
/// authorization_code + refresh_token grants, provisioned on the AUTHORIZE
/// endpoint's unknown-client path. PAR-first flows (FAPI-profiled clients)
/// and private_key_jwt authentication are future extensions; the persisted
/// row makes subsequent token/refresh requests work without re-fetching.
/// </para>
/// <para>
/// Existing rows are never re-fetched in this version: a client that changes
/// its document picks the changes up only after the row is removed (the
/// document cache governs re-fetch frequency while the row is absent).
/// </para>
/// </remarks>
public sealed class CimdApplicationProvisioner(
    IOpenIddictApplicationManager applications,
    ClientIdMetadataResolver resolver,
    SufficitIdentityOptions rootOptions,
    ILogger<CimdApplicationProvisioner> logger)
{
    /// <summary>
    /// Returns the existing application for <paramref name="clientId"/>, or
    /// provisions one from the client's CIMD document when the feature is
    /// enabled and the identifier has the CIMD shape. Null means "not a CIMD
    /// client / provisioning rejected" — the caller surfaces its normal
    /// unknown-client error.
    /// </summary>
    public async Task<object?> TryProvisionAsync(
        string clientId,
        CancellationToken cancellationToken = default)
    {
        var options = rootOptions.Mcp.ClientIdMetadataDocuments;
        if (!options.Enabled
            || !ClientIdMetadataResolver.IsCimdCandidate(clientId))
        {
            return null;
        }

        var existing = await applications.FindByClientIdAsync(
            clientId, cancellationToken);
        if (existing is not null)
        {
            return existing;
        }

        var document = await resolver.ResolveAsync(clientId, cancellationToken);
        if (document is null)
        {
            logger.LogWarning(
                "CIMD document for {ClientId} was rejected; refusing to " +
                "provision the client.",
                clientId);
            return null;
        }

        var dcrPolicy = rootOptions.Mcp.Dcr;
        var descriptor = new OpenIddictApplicationDescriptor
        {
            ClientId = document.ClientId,
            DisplayName = document.ClientName ?? document.ClientId,
            // Same secure defaults as every other dynamically provisioned
            // client: explicit consent, public, PKCE required.
            ConsentType = ConsentTypes.Explicit,
            ClientType = ClientTypes.Public,
        };

        var hasAuthorizationCode = false;
        foreach (var grant in document.GrantTypes)
        {
            if (!dcrPolicy.AllowedGrantTypes.Contains(grant))
            {
                continue;
            }

            if (grant == GrantTypes.AuthorizationCode)
            {
                hasAuthorizationCode = true;
                descriptor.Permissions.Add(Permissions.GrantTypes.AuthorizationCode);
                descriptor.Permissions.Add(Permissions.Endpoints.Authorization);
                descriptor.Permissions.Add(Permissions.ResponseTypes.Code);
                descriptor.Requirements.Add(
                    Requirements.Features.ProofKeyForCodeExchange);
            }
            else if (grant == GrantTypes.RefreshToken)
            {
                descriptor.Permissions.Add(Permissions.GrantTypes.RefreshToken);
            }
        }
        descriptor.Permissions.Add(Permissions.Endpoints.Token);

        foreach (var scope in document.Scopes)
        {
            if (dcrPolicy.AllowedScopes.Contains(scope))
            {
                descriptor.Permissions.Add(Permissions.Prefixes.Scope + scope);
            }
        }

        foreach (var redirect in document.RedirectUris)
        {
            descriptor.RedirectUris.Add(new Uri(redirect, UriKind.Absolute));
        }

        if (hasAuthorizationCode && descriptor.RedirectUris.Count == 0)
        {
            // The resolver guarantees at least one redirect for the code
            // grant; this is defense in depth for future grant combinations.
            return null;
        }

        var created = await applications.CreateAsync(
            descriptor, cancellationToken);
        logger.LogInformation(
            "Provisioned CIMD client {ClientId} (redirects={RedirectCount}, " +
            "grants={Grants}).",
            document.ClientId,
            descriptor.RedirectUris.Count,
            string.Join(',', document.GrantTypes));
        return created;
    }
}
