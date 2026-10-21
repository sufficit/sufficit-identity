using System.Collections.Immutable;
using System.Globalization;
using System.Text.Json;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Logging;
using OpenIddict.Abstractions;
using Sufficit.Identity.Core.Services;
using static OpenIddict.Abstractions.OpenIddictConstants;

namespace Sufficit.Identity.STS.Grants;

/// <summary>Names of the system-user enrollment grant.</summary>
public static class SystemUserEnrollmentGrant
{
    /// <inheritdoc cref="Management.SystemUsers.SystemUserEnrollmentProtocol.GrantType"/>
    public const string GrantType = Management.SystemUsers.SystemUserEnrollmentProtocol.GrantType;

    /// <inheritdoc cref="Management.SystemUsers.SystemUserEnrollmentProtocol.CodeParameter"/>
    public const string CodeParameter = Management.SystemUsers.SystemUserEnrollmentProtocol.CodeParameter;

    /// <summary>Recorded as the delegator of the credential's authorization.</summary>
    public const string Issuer = "system-user-enrollment";
}

/// <summary>Configuration of system-user credentials.</summary>
public sealed class SystemUserOptions
{
    public const int MaxCredentialLifetimeDays = 730;

    /// <summary>
    /// Absolute lifetime of a credential obtained by enrollment. Refreshing
    /// never extends it; re-enrolling issues a new one.
    /// </summary>
    public int CredentialLifetimeDays { get; init; } = 365;
}

/// <summary>
/// Redeems an enrollment code: the authenticated client presents the code the
/// operator issued for it and receives a refresh token (plus an access token)
/// in the system user's name. With a DPoP proof on the request the credential
/// is bound to that key for its whole life. A provisioner redeeming on behalf
/// of a device that never lets its key out names that key with
/// <c>dpop_jkt</c> instead (as the delegated credential does); the device then
/// proves possession on every refresh. The credential travels the
/// delegated-credential path afterwards: fixed scopes, absolute deadline,
/// revocable through its authorization.
/// </summary>
public sealed class SystemUserEnrollmentGrantHandler(
    SystemUserStore systemUsers,
    IOpenIddictAuthorizationManager authorizations,
    SystemUserOptions options,
    ILogger<SystemUserEnrollmentGrantHandler> logger) : ITokenGrantHandler
{
    private const string InvalidCode =
        "The enrollment code is invalid, expired, revoked or already used.";

    public IReadOnlyCollection<string> HandledGrantTypes { get; } = [SystemUserEnrollmentGrant.GrantType];

    public async Task<IActionResult> HandleAsync(TokenGrantContext context)
    {
        var (httpContext, request, proof, ops) =
            (context.HttpContext, context.Request, context.Proof, context.Operations);
        var ct = httpContext.RequestAborted;
        var clientId = request.ClientId!;

        var enrollment = await systemUsers.FindRedeemableAsync(
            (string?)request.GetParameter(SystemUserEnrollmentGrant.CodeParameter), ct);
        // A code names its client: another client presenting it learns nothing.
        if (enrollment is null || !string.Equals(enrollment.ClientId, clientId, StringComparison.Ordinal))
        {
            return TokenGrantDispatcher.ForbidError(Errors.InvalidGrant, InvalidCode);
        }

        var system = await systemUsers.FindAsync(enrollment.UserId, ct);
        var user = await ops.UserManager.FindByIdAsync(enrollment.UserId);
        if (system is null || system.DisabledAtUtc is not null || user is null)
        {
            return TokenGrantDispatcher.ForbidError(Errors.InvalidGrant, InvalidCode);
        }

        // Bind to the named key when given; a proof for another key contradicts it.
        var boundKey = proof?.KeyThumbprint;
        if (request.GetParameter(DelegatedCredential.DpopJktParameter) is { } jktParameter)
        {
            var jkt = (string?)jktParameter;
            if (!DelegatedCredential.IsValidThumbprint(jkt))
            {
                return TokenGrantDispatcher.ForbidError(Errors.InvalidRequest,
                    "dpop_jkt must be the base64url SHA-256 JWK thumbprint (RFC 7638) of the device key.");
            }

            if (proof is not null && !string.Equals(proof.KeyThumbprint, jkt, StringComparison.Ordinal))
            {
                return TokenGrantDispatcher.ForbidError(Errors.InvalidRequest,
                    "The dpop_jkt parameter does not match the key of the DPoP proof.");
            }

            boundKey = jkt;
        }

        var application = await ops.ApplicationManager.FindByClientIdAsync(clientId, ct);
        if (application is null
            || !await ops.ApplicationManager.HasPermissionAsync(
                application, Permissions.GrantTypes.RefreshToken, ct))
        {
            return TokenGrantDispatcher.ForbidError(Errors.UnauthorizedClient,
                "The client is not registered for refresh tokens.");
        }

        // Checked last so a request refused for another reason does not burn
        // the code; of two concurrent redemptions exactly one gets here.
        if (!await systemUsers.TryRedeemAsync(enrollment.Id, ct))
        {
            return TokenGrantDispatcher.ForbidError(Errors.InvalidGrant, InvalidCode);
        }

        var scopes = await ResolveScopesAsync(ops.ApplicationManager, application, request.GetScopes(), ct);
        var now = DateTimeOffset.UtcNow;
        var lifetimeDays = Math.Clamp(options.CredentialLifetimeDays, 1, SystemUserOptions.MaxCredentialLifetimeDays);
        var expiresAt = now.AddDays(lifetimeDays);
        var label = enrollment.Id.ToString("D");

        var descriptor = new OpenIddictAuthorizationDescriptor
        {
            ApplicationId = await ops.ApplicationManager.GetIdAsync(application, ct),
            CreationDate = now,
            Status = Statuses.Valid,
            Subject = user.Id,
            Type = AuthorizationTypes.AdHoc,
        };
        descriptor.Scopes.UnionWith(scopes);
        descriptor.Properties[DelegatedCredential.AuthorizationPropertyName] =
            JsonSerializer.SerializeToElement(new DelegatedCredentialRecord(
                label, SystemUserEnrollmentGrant.Issuer, expiresAt.ToUnixTimeSeconds()));
        var authorization = await authorizations.CreateAsync(descriptor, ct);
        var authorizationId = (await authorizations.GetIdAsync(authorization, ct))!;
        await systemUsers.SetAuthorizationAsync(enrollment.Id, authorizationId, ct);

        var identity = await ops.BuildIdentityAsync(user);
        identity.SetScopes(scopes);
        identity.SetResources(await ops.ResolveResourcesAsync(identity, request));
        identity.SetPresenters(clientId);
        identity.SetAuthorizationId(authorizationId);
        identity.SetRefreshTokenLifetime(expiresAt - now);
        identity.SetClaim(DelegatedCredential.ExpiresAtClaimType,
            expiresAt.ToUnixTimeSeconds().ToString(CultureInfo.InvariantCulture));
        identity.SetClaim(DelegatedCredential.LabelClaimType, label);
        if (boundKey is not null)
        {
            identity.SetClaim(Dpop.DpopProofValidator.BindingThumbprintClaimType, boundKey);
        }

        logger.LogInformation(
            "System user {UserId} enrolled client {ClientId} (enrollment {EnrollmentId}, DPoP bound: {Bound}).",
            user.Id, clientId, enrollment.Id, boundKey is not null);

        return ops.SignIn(identity, request);
    }

    /// <summary>
    /// The scopes the client is registered for, narrowed to the requested ones
    /// when the request names any, plus <c>offline_access</c>: the credential
    /// is a refresh token and OpenIddict only rotates refresh tokens whose
    /// grant carries that scope.
    /// </summary>
    internal static async Task<ImmutableArray<string>> ResolveScopesAsync(
        IOpenIddictApplicationManager applications,
        object application,
        ImmutableArray<string> requested,
        CancellationToken ct)
    {
        var permitted = (await applications.GetPermissionsAsync(application, ct))
            .Where(permission => permission.StartsWith(Permissions.Prefixes.Scope, StringComparison.Ordinal))
            .Select(permission => permission[Permissions.Prefixes.Scope.Length..])
            .ToHashSet(StringComparer.Ordinal);
        permitted.Add(Scopes.OpenId);

        var granted = new SortedSet<string>(StringComparer.Ordinal) { Scopes.OfflineAccess };
        foreach (var scope in requested.Length > 0 ? requested.AsEnumerable() : permitted)
        {
            if (permitted.Contains(scope))
            {
                granted.Add(scope);
            }
        }

        return [.. granted];
    }
}
