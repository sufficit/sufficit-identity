using System.Collections.Immutable;
using System.Globalization;
using System.Security.Claims;
using System.Text.Json;
using Microsoft.AspNetCore.Mvc;
using OpenIddict.Abstractions;
using Sufficit.Identity.Core.Entities;
using static OpenIddict.Abstractions.OpenIddictConstants;

namespace Sufficit.Identity.STS.Grants;

/// <summary>
/// Issues a delegated device credential: the token-exchange branch selected by
/// <c>requested_token_type=refresh_token</c> with the configured delegate
/// client as <c>audience</c> (see <see cref="DelegatedCredentialOptions"/>).
/// </summary>
/// <remarks>
/// <para>The general token-exchange rules are replaced, not relaxed: the
/// subject token must be a user access token issued to the caller and
/// carrying the delegation scope, the sign-in behind it must be recent, the
/// caller must be on the delegator allow-list, and the result belongs to the
/// delegate client, bound to the DPoP key named by <c>dpop_jkt</c>. The
/// caller never receives anything usable without that key.</para>
/// <para>The issued refresh token travels in <c>access_token</c> with
/// <c>issued_token_type=urn:ietf:params:oauth:token-type:refresh_token</c>
/// (RFC 8693 §2.2.1). The device redeems it with the refresh_token grant as
/// the delegate client and a DPoP proof made with the bound key; that and
/// every later refresh return DPoP-bound access tokens.</para>
/// </remarks>
public sealed class DelegatedCredentialIssuer(
    TokenExchangeOptions tokenExchangeOptions,
    IOpenIddictAuthorizationManager authorizations,
    IOpenIddictTokenManager tokens,
    DelegatedCredentialEvents events,
    TimeProvider timeProvider)
{
    /// <summary>Whether the request selected this mode (audience deferred).</summary>
    public static bool IsRequested(OpenIddictRequest request) =>
        request.IsTokenExchangeGrantType()
        && string.Equals(request.RequestedTokenType,
            TokenTypeIdentifiers.RefreshToken, StringComparison.Ordinal)
        && !string.IsNullOrEmpty((string?)request.GetParameter(
            DelegatedCredential.AudienceParameter));

    public async Task<IActionResult> IssueAsync(
        TokenGrantContext context,
        ClaimsPrincipal subjectToken)
    {
        var (httpContext, request, ops) =
            (context.HttpContext, context.Request, context.Operations);
        var options = tokenExchangeOptions.DelegatedCredentials;
        var ct = httpContext.RequestAborted;
        var caller = request.ClientId!;
        var subject = subjectToken.GetClaim(Claims.Subject);
        var rawLabel = (string?)request.GetParameter(DelegatedCredential.LabelParameter);

        async Task<IActionResult> RefuseAsync(string error, string description, string reason)
        {
            await events.RecordRefusalAsync(subject ?? caller, caller, reason,
                DelegatedCredential.TryNormalizeLabel(rawLabel, out var label) ? label : null,
                ct);
            return TokenGrantDispatcher.ForbidError(error, description);
        }

        if (!options.Enabled
            || !string.Equals((string?)request.GetParameter(DelegatedCredential.AudienceParameter),
                options.DelegateClientId, StringComparison.Ordinal))
        {
            return TokenGrantDispatcher.ForbidError(Errors.InvalidRequest,
                "Delegated credentials are not issued by this server.");
        }

        if (!options.DelegatorClientIds.Contains(caller))
        {
            return await RefuseAsync(Errors.UnauthorizedClient,
                "This client is not allowed to delegate credentials.", "caller_not_allowed");
        }

        if (!string.IsNullOrEmpty(request.ActorToken))
        {
            return await RefuseAsync(Errors.InvalidRequest,
                "actor_token is not supported when delegating a credential.", "actor_token_present");
        }

        if (!string.Equals(request.SubjectTokenType, TokenTypeIdentifiers.AccessToken, StringComparison.Ordinal)
            || !string.Equals(subjectToken.GetTokenType(), TokenTypeIdentifiers.AccessToken, StringComparison.Ordinal))
        {
            return await RefuseAsync(Errors.InvalidRequest,
                "A delegated credential requires a user access token as subject_token.", "subject_not_access_token");
        }

        // The subject token must name the caller as its ONLY authorized
        // party: a token the caller merely received for a resource it serves
        // does not show that the user signed in to the caller.
        var parties = TokenExchangeGrantHandler.AuthorizedParties(subjectToken);
        if (parties.Length != 1 || !string.Equals(parties[0], caller, StringComparison.Ordinal))
        {
            return await RefuseAsync(Errors.InvalidGrant,
                "The subject_token was not issued to this client.", "subject_not_issued_to_caller");
        }

        var user = subject is not null ? await ops.UserManager.FindByIdAsync(subject) : null;
        if (user is null)
        {
            return await RefuseAsync(Errors.InvalidGrant,
                "The subject_token does not identify a user.", "subject_not_user");
        }

        if (!await ops.SignInManager.CanSignInAsync(user))
        {
            return await RefuseAsync(Errors.InvalidGrant,
                "The subject_token no longer identifies a user that is allowed to sign in.", "user_not_allowed");
        }

        var subjectScopes = subjectToken.GetScopes();
        if (!subjectScopes.Contains(options.RequiredScope, StringComparer.Ordinal))
        {
            return await RefuseAsync(Errors.InvalidScope,
                "The subject_token does not carry the scope that authorizes delegation.", "missing_delegation_scope");
        }

        var now = timeProvider.GetUtcNow();
        var authenticatedAt = ReadAuthenticationTime(subjectToken);
        if (authenticatedAt is null)
        {
            return await RefuseAsync(Errors.InvalidGrant,
                "The subject_token does not record when the user signed in.", "missing_auth_time");
        }

        if (!IsRecent(authenticatedAt.Value, now, options.MaxAuthAgeHours))
        {
            return await RefuseAsync(Errors.InvalidGrant,
                "The user's sign-in is too old to delegate a credential. Sign in again and retry.", "stale_authentication");
        }

        var jkt = (string?)request.GetParameter(DelegatedCredential.DpopJktParameter);
        if (!DelegatedCredential.IsValidThumbprint(jkt))
        {
            return await RefuseAsync(Errors.InvalidRequest,
                "dpop_jkt must be the base64url SHA-256 JWK thumbprint (RFC 7638) of the device key.", "invalid_dpop_jkt");
        }

        if (!DelegatedCredential.TryNormalizeLabel(rawLabel, out var label))
        {
            return await RefuseAsync(Errors.InvalidRequest,
                "executor_id must be a UUID identifying the device.", "invalid_label");
        }

        if (subjectToken.GetClaim(GrantOperations.MayActClaimType) is { } mayAct
            && !TokenExchangeGrantHandler.MayActAuthorizes(mayAct, caller, caller))
        {
            return await RefuseAsync(Errors.InvalidGrant,
                "The subject_token does not authorize this actor (may_act).", "may_act_mismatch");
        }

        var priorAct = subjectToken.GetClaim(GrantOperations.ActClaimType);
        var priorDepth = TokenExchangeGrantHandler.DelegationDepth(priorAct);
        if (priorDepth is null || priorDepth.Value + 1 > tokenExchangeOptions.MaxDelegationDepth)
        {
            return await RefuseAsync(Errors.InvalidGrant,
                "The subject_token's delegation chain cannot be extended.", "delegation_depth");
        }

        var delegateApplication = await ops.ApplicationManager.FindByClientIdAsync(options.DelegateClientId, ct);
        if (delegateApplication is null
            || !await ops.ApplicationManager.HasPermissionAsync(
                delegateApplication, Permissions.GrantTypes.RefreshToken, ct))
        {
            return await RefuseAsync(Errors.InvalidRequest,
                "The delegate client is not registered for refresh tokens.", "delegate_not_registered");
        }

        var delegateApplicationId = (await ops.ApplicationManager.GetIdAsync(delegateApplication, ct))!;
        var scopes = await ResolveScopesAsync(ops.ApplicationManager, delegateApplication,
            subjectScopes, request.GetScopes(), options.RequiredScope, ct);

        // Per-user cap and same-label replacement. Concurrent delegations for
        // one user can overshoot the cap by the number of racing requests;
        // the cap bounds accumulation, it is not a lock.
        var (active, replaced) = await InventoryAsync(user.Id, delegateApplicationId, label, now, ct);
        if (active >= options.MaxActivePerUser)
        {
            return await RefuseAsync(Errors.InvalidRequest,
                string.Create(CultureInfo.InvariantCulture,
                    $"This account already has {active} active delegated credentials (limit {options.MaxActivePerUser}). Revoke one before delegating another."),
                "cap_exceeded");
        }

        foreach (var previous in replaced)
        {
            await RevokeAsync(previous, ct);
        }

        var expiresAt = now.AddDays(options.CredentialLifetimeDays);
        var descriptor = new OpenIddictAuthorizationDescriptor
        {
            ApplicationId = delegateApplicationId,
            CreationDate = now,
            Status = Statuses.Valid,
            Subject = user.Id,
            Type = AuthorizationTypes.AdHoc,
        };
        descriptor.Scopes.UnionWith(scopes);
        descriptor.Properties[DelegatedCredential.AuthorizationPropertyName] =
            JsonSerializer.SerializeToElement(new DelegatedCredentialRecord(
                label, caller, expiresAt.ToUnixTimeSeconds()));
        var authorization = await authorizations.CreateAsync(descriptor, ct);
        var authorizationId = (await authorizations.GetIdAsync(authorization, ct))!;

        var identity = await ops.BuildIdentityAsync(user, subjectToken);
        identity.SetScopes(scopes);
        identity.SetResources(await ops.ResolveResourcesAsync(identity, null));
        identity.SetPresenters(options.DelegateClientId);
        identity.SetAuthorizationId(authorizationId);
        identity.SetRefreshTokenLifetime(expiresAt - now);
        identity.SetClaim(Dpop.DpopProofValidator.BindingThumbprintClaimType, jkt);
        identity.SetClaim(DelegatedCredential.ExpiresAtClaimType,
            expiresAt.ToUnixTimeSeconds().ToString(CultureInfo.InvariantCulture));
        identity.SetClaim(DelegatedCredential.LabelClaimType, label);

        // RFC 8693 §4.1: the delegating client is the actor, nesting whatever
        // chain the subject token already carried.
        var act = new Dictionary<string, object> { ["sub"] = caller };
        if (priorAct is not null)
        {
            act["act"] = JsonSerializer.Deserialize<JsonElement>(priorAct);
        }

        identity.SetClaim(GrantOperations.ActClaimType, JsonSerializer.SerializeToElement(act));

        var replacedIds = replaced.Select(item => item.Id).ToArray();
        if (!await events.RecordIssuedAsync(user, authorizationId, caller, options.DelegateClientId,
                label, scopes, expiresAt, replacedIds, ct))
        {
            await RevokeAsync(new ExistingCredential(authorizationId, authorization), ct);
            return TokenGrantDispatcher.ForbidError("temporarily_unavailable",
                "The delegation could not be recorded. Please retry.");
        }

        if (options.NotifyOnIssue)
        {
            var callerApplication = await ops.ApplicationManager.FindByClientIdAsync(caller, ct);
            var callerName = callerApplication is null
                ? caller
                : await ops.ApplicationManager.GetDisplayNameAsync(callerApplication, ct) ?? caller;
            await events.NotifyIssuedAsync(user, callerName, label, expiresAt);
        }

        return ops.SignIn(identity, request);
    }

    /// <summary>
    /// Delegate permissions ∩ subject-token scopes (∩ the request's scopes,
    /// when given), never the delegation scope itself, plus
    /// <c>offline_access</c>: the credential IS a refresh token, and OpenIddict
    /// only rotates refresh tokens whose grant carries that scope.
    /// </summary>
    internal static async Task<ImmutableArray<string>> ResolveScopesAsync(
        IOpenIddictApplicationManager applications,
        object delegateApplication,
        ImmutableArray<string> subjectScopes,
        ImmutableArray<string> requestedScopes,
        string requiredScope,
        CancellationToken ct)
    {
        var granted = new SortedSet<string>(StringComparer.Ordinal) { Scopes.OfflineAccess };
        foreach (var scope in subjectScopes)
        {
            if (string.Equals(scope, requiredScope, StringComparison.Ordinal)
                || (requestedScopes.Length > 0 && !requestedScopes.Contains(scope, StringComparer.Ordinal)))
            {
                continue;
            }

            if (string.Equals(scope, Scopes.OpenId, StringComparison.Ordinal)
                || await applications.HasPermissionAsync(
                    delegateApplication, Permissions.Prefixes.Scope + scope, ct))
            {
                granted.Add(scope);
            }
        }

        return [.. granted];
    }

    internal static bool IsRecent(DateTimeOffset authenticatedAt, DateTimeOffset now, int maxAgeHours) =>
        authenticatedAt <= now.AddMinutes(5)
        && now - authenticatedAt <= TimeSpan.FromHours(maxAgeHours);

    private static DateTimeOffset? ReadAuthenticationTime(ClaimsPrincipal principal)
    {
        if (!long.TryParse(principal.GetClaim(AuthenticationContextProjector.AuthenticationTimeClaimType),
                NumberStyles.Integer, CultureInfo.InvariantCulture, out var seconds))
        {
            return null;
        }

        try
        {
            return DateTimeOffset.FromUnixTimeSeconds(seconds);
        }
        catch (ArgumentOutOfRangeException)
        {
            return null;
        }
    }

    private async Task<(int Active, List<ExistingCredential> Replaced)> InventoryAsync(
        string userId, string delegateApplicationId, string label, DateTimeOffset now, CancellationToken ct)
    {
        var active = 0;
        var replaced = new List<ExistingCredential>();
        await foreach (var authorization in authorizations.FindAsync(
            userId, delegateApplicationId, Statuses.Valid, type: null, scopes: null, ct))
        {
            var properties = await authorizations.GetPropertiesAsync(authorization, ct);
            if (!DelegatedCredentialRecord.TryRead(properties, out var record))
            {
                continue;
            }

            var id = (await authorizations.GetIdAsync(authorization, ct))!;
            if (string.Equals(record.Label, label, StringComparison.Ordinal))
            {
                replaced.Add(new ExistingCredential(id, authorization));
            }
            else if (record.ExpiresAt > now.ToUnixTimeSeconds())
            {
                active++;
            }
        }

        return (active, replaced);
    }

    private async Task RevokeAsync(ExistingCredential credential, CancellationToken ct)
    {
        await tokens.RevokeByAuthorizationIdAsync(credential.Id, ct);
        await authorizations.TryRevokeAsync(credential.Authorization, ct);
    }

    private sealed record ExistingCredential(string Id, object Authorization);
}

/// <summary>
/// The <see cref="DelegatedCredential.AuthorizationPropertyName"/> property of
/// a delegated credential's authorization.
/// </summary>
public sealed record DelegatedCredentialRecord(
    [property: System.Text.Json.Serialization.JsonPropertyName("label")] string Label,
    [property: System.Text.Json.Serialization.JsonPropertyName("delegator")] string Delegator,
    [property: System.Text.Json.Serialization.JsonPropertyName("expires_at")] long ExpiresAt)
{
    public static bool TryRead(
        IReadOnlyDictionary<string, JsonElement> properties,
        out DelegatedCredentialRecord record)
    {
        record = null!;
        if (!properties.TryGetValue(DelegatedCredential.AuthorizationPropertyName, out var element)
            || element.ValueKind != JsonValueKind.Object)
        {
            return false;
        }

        try
        {
            var parsed = element.Deserialize<DelegatedCredentialRecord>();
            if (parsed is null || string.IsNullOrEmpty(parsed.Label))
            {
                return false;
            }

            record = parsed;
            return true;
        }
        catch (JsonException)
        {
            return false;
        }
    }
}
