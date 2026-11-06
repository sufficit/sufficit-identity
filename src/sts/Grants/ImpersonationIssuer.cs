using System.Globalization;
using System.Security.Claims;
using System.Text.Json;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Logging;
using OpenIddict.Abstractions;
using Sufficit.Identity.Core.Data;
using Sufficit.Identity.Core.Entities;
using Sufficit.Identity.Management.Authorization;
using Sufficit.Identity.Application.Security;
using static OpenIddict.Abstractions.OpenIddictConstants;

namespace Sufficit.Identity.STS.Grants;

/// <summary>Configuration of staff impersonation (<c>Sufficit:Identity:TokenExchange:Impersonation</c>).</summary>
public sealed class ImpersonationOptions
{
    /// <summary>Off unless a deployment turns it on.</summary>
    public bool Enabled { get; init; }

    /// <summary>Clients that may request an impersonation token; empty refuses every client.</summary>
    public HashSet<string> AllowedClientIds { get; init; } = new(StringComparer.Ordinal);

    /// <summary>How long the issued access token lives (clamped to 5–60 minutes).</summary>
    public int AccessTokenLifetimeMinutes { get; init; } = 30;

    /// <summary>The staff sign-in behind the subject token must be at most this old.</summary>
    public int MaxAuthAgeMinutes { get; init; } = 480;

    /// <summary>The staff sign-in must carry a second factor that was presented, not remembered.</summary>
    public bool RequireSecondFactor { get; init; } = true;
}

/// <summary>
/// Staff impersonation: the token-exchange branch selected by the
/// <c>impersonated_subject</c> parameter. The caller presents the staff member's
/// own access token as <c>subject_token</c> and names the person to act as. The
/// result is a short-lived access token whose <c>sub</c> is that person and whose
/// <c>act</c> names the staff member (RFC 8693 §4.1), so every resource resolves
/// the person's real permissions while still seeing who is acting.
/// </summary>
/// <remarks>
/// Rules replace the general token-exchange ones: an allow-listed client, a
/// staff token issued to that client with a recent sign-in (second factor when
/// required), the <see cref="ManagementCapabilities.UsersImpersonate"/>
/// capability through the staff member's roles, and a target that can sign in
/// and is not an administrator, a manager role holder or a protected principal.
/// No refresh token; no nested impersonation. Every decision is audited and
/// kept forever; when the issuance cannot be audited nothing is issued.
/// </remarks>
public sealed class ImpersonationIssuer(
    TokenExchangeOptions tokenExchangeOptions,
    IConfiguration configuration,
    ImpersonationEvents events,
    TimeProvider timeProvider)
{
    public const string SubjectParameter = "impersonated_subject";

    public static bool IsRequested(OpenIddictRequest request) =>
        request.IsTokenExchangeGrantType()
        && !string.IsNullOrEmpty((string?)request.GetParameter(SubjectParameter));

    public async Task<IActionResult> IssueAsync(TokenGrantContext context, ClaimsPrincipal subjectToken)
    {
        var (httpContext, request, ops) = (context.HttpContext, context.Request, context.Operations);
        var options = tokenExchangeOptions.Impersonation;
        var ct = httpContext.RequestAborted;
        var caller = request.ClientId!;
        var actorId = subjectToken.GetClaim(Claims.Subject);
        var targetId = (string?)request.GetParameter(SubjectParameter);

        async Task<IActionResult> RefuseAsync(string error, string description, string reason)
        {
            await events.RecordRefusalAsync(actorId ?? caller, targetId, caller, reason, ct);
            return TokenGrantDispatcher.ForbidError(error, description);
        }

        if (!options.Enabled)
        {
            return TokenGrantDispatcher.ForbidError(Errors.InvalidRequest, "Impersonation is not available on this server.");
        }
        if (!options.AllowedClientIds.Contains(caller))
        {
            return await RefuseAsync(Errors.UnauthorizedClient, "This client is not allowed to impersonate.", "caller_not_allowed");
        }
        if (!string.IsNullOrEmpty(request.ActorToken))
        {
            return await RefuseAsync(Errors.InvalidRequest, "actor_token is not used for impersonation.", "actor_token_present");
        }
        if (!string.Equals(request.SubjectTokenType, TokenTypeIdentifiers.AccessToken, StringComparison.Ordinal)
            || !string.Equals(subjectToken.GetTokenType(), TokenTypeIdentifiers.AccessToken, StringComparison.Ordinal))
        {
            return await RefuseAsync(Errors.InvalidRequest, "Impersonation requires the staff access token as subject_token.", "subject_not_access_token");
        }
        var parties = TokenExchangeGrantHandler.AuthorizedParties(subjectToken);
        if (parties.Length != 1 || !string.Equals(parties[0], caller, StringComparison.Ordinal))
        {
            return await RefuseAsync(Errors.InvalidGrant, "The subject_token was not issued to this client.", "subject_not_issued_to_caller");
        }
        if (subjectToken.GetClaim(GrantOperations.ActClaimType) is not null)
        {
            return await RefuseAsync(Errors.InvalidGrant, "An impersonated or delegated token cannot impersonate.", "subject_already_acting");
        }

        var actor = actorId is null ? null : await ops.UserManager.FindByIdAsync(actorId);
        if (actor is null || !await ops.SignInManager.CanSignInAsync(actor))
        {
            return await RefuseAsync(Errors.InvalidGrant, "The subject_token no longer identifies a user that is allowed to sign in.", "actor_not_allowed");
        }

        var now = timeProvider.GetUtcNow();
        if (!IsRecentSignIn(subjectToken, now, options.MaxAuthAgeMinutes))
        {
            return await RefuseAsync(Errors.InvalidGrant, "Sign in again before impersonating.", "sign_in_not_recent");
        }
        if (options.RequireSecondFactor
            && (!MfaEvidencePolicy.HasMfaEvidence(subjectToken) || MfaEvidencePolicy.IsSecondFactorRemembered(subjectToken)))
        {
            return await RefuseAsync(Errors.InvalidGrant, "Impersonation requires a sign-in with a second factor.", "second_factor_required");
        }

        var authorization = configuration.GetSection("Sufficit:Identity:Management:Authorization")
            .Get<ManagementAuthorizationOptions>() ?? new ManagementAuthorizationOptions();
        if (!HasCapability(await ops.UserManager.GetRolesAsync(actor), authorization, ManagementCapabilities.UsersImpersonate))
        {
            return await RefuseAsync(Errors.AccessDenied, "This account may not impersonate.", "capability_missing");
        }

        var target = targetId is null ? null : await ops.UserManager.FindByIdAsync(targetId);
        if (target is null || string.Equals(target.Id, actor.Id, StringComparison.Ordinal))
        {
            return await RefuseAsync(Errors.InvalidRequest, "The person to impersonate was not found.", "target_not_found");
        }
        if (!await ops.SignInManager.CanSignInAsync(target))
        {
            return await RefuseAsync(Errors.InvalidRequest, "The person to impersonate cannot sign in.", "target_not_allowed");
        }
        if (IsPrivileged(target.Id, await ops.UserManager.GetRolesAsync(target), authorization))
        {
            return await RefuseAsync(Errors.AccessDenied, "Administrators, managers and protected accounts cannot be impersonated.", "target_privileged");
        }

        var identity = await ops.BuildIdentityAsync(target, subjectToken, httpContext.User);
        var requestedScopes = request.GetScopes();
        var subjectScopes = subjectToken.GetScopes();
        identity.SetScopes((requestedScopes.Length > 0 ? requestedScopes.Intersect(subjectScopes) : subjectScopes)
            .Where(scope => !string.Equals(scope, Scopes.OfflineAccess, StringComparison.Ordinal)));
        var subjectResources = subjectToken.GetResources().Concat(subjectToken.GetAudiences()).ToHashSet(StringComparer.Ordinal);
        if (request.GetResources().Any(resource => !subjectResources.Contains(resource)))
        {
            return await RefuseAsync(Errors.InvalidTarget, "The requested resource is not authorized by the subject_token.", "resource_not_authorized");
        }
        identity.SetResources((await ops.ResolveResourcesAsync(identity, request)).Intersect(subjectResources));
        identity.SetClaim(GrantOperations.ActClaimType, JsonSerializer.SerializeToElement(
            new Dictionary<string, object> { ["sub"] = actor.Id, ["client_id"] = caller }));
        var lifetime = TimeSpan.FromMinutes(Math.Clamp(options.AccessTokenLifetimeMinutes, 5, 60));
        identity.SetAccessTokenLifetime(lifetime);
        GrantOperations.ApplyDpopBinding(identity, context.Proof);

        if (!await events.RecordIssuedAsync(actor, target, caller, identity.GetScopes(), now + lifetime, ct))
        {
            return TokenGrantDispatcher.ForbidError(Errors.ServerError, "Impersonation could not be audited, so it was not issued.");
        }
        return ops.SignIn(identity, request);
    }

    internal static bool IsRecentSignIn(ClaimsPrincipal principal, DateTimeOffset now, int maxAgeMinutes)
    {
        if (!long.TryParse(principal.GetClaim(AuthenticationContextProjector.AuthenticationTimeClaimType),
                NumberStyles.Integer, CultureInfo.InvariantCulture, out var seconds)) return false;
        DateTimeOffset at;
        try { at = DateTimeOffset.FromUnixTimeSeconds(seconds); }
        catch (ArgumentOutOfRangeException) { return false; }
        return at <= now.AddMinutes(5) && now - at <= TimeSpan.FromMinutes(Math.Max(1, maxAgeMinutes));
    }

    /// <summary>Same mapping as the management API: full administrator roles hold every capability.</summary>
    internal static bool HasCapability(IEnumerable<string> roles, ManagementAuthorizationOptions options, string capability)
        => roles.Any(role => options.FullAdministratorRoles.Contains(role, StringComparer.OrdinalIgnoreCase)
            || (options.RoleCapabilities.TryGetValue(role, out var capabilities)
                && capabilities.Contains(capability, StringComparer.OrdinalIgnoreCase)));

    /// <summary>Anyone holding management authority or marked protected is out of reach.</summary>
    internal static bool IsPrivileged(string userId, IEnumerable<string> roles, ManagementAuthorizationOptions options)
    {
        if (options.ProtectedPrincipals.ProtectedUserIds.Contains(userId, StringComparer.OrdinalIgnoreCase)) return true;
        return roles.Any(role => string.Equals(role, "administrator", StringComparison.OrdinalIgnoreCase)
            || string.Equals(role, "manager", StringComparison.OrdinalIgnoreCase)
            || options.FullAdministratorRoles.Contains(role, StringComparer.OrdinalIgnoreCase)
            || options.RoleCapabilities.ContainsKey(role)
            || options.ProtectedPrincipals.ProtectedRoles.Contains(role, StringComparer.OrdinalIgnoreCase));
    }
}

/// <summary>Audit trail of impersonation: one row per decision, never expiring, no token content.</summary>
public sealed class ImpersonationEvents(
    AppDbContext database,
    IHttpContextAccessor httpContextAccessor,
    ILogger<ImpersonationEvents> logger)
{
    public async Task RecordRefusalAsync(string actor, string? target, string callerClientId, string reason, CancellationToken ct)
    {
        logger.LogWarning("Impersonation refused for {Actor} -> {Target} by client {ClientId}: {Reason}.",
            Sanitize(actor), Sanitize(target), Sanitize(callerClientId), reason);
        await WriteAsync(new ManagementAuditEvent
        {
            OperatorSubject = Truncate(actor, 255),
            Capability = ManagementCapabilities.UsersImpersonate,
            ResourceType = "user",
            ResourceId = Truncate(target, 255),
            AuthorizationOutcome = "denied",
            OperationOutcome = "refused",
            ReasonCode = Truncate(reason, 100),
            AfterJson = JsonSerializer.Serialize(new { client = callerClientId }),
        }, ct);
    }

    /// <returns><see langword="false"/> when the row could not be written; nothing is issued then.</returns>
    public async Task<bool> RecordIssuedAsync(ApplicationUser actor, ApplicationUser target, string callerClientId,
        IEnumerable<string> scopes, DateTimeOffset expiresAt, CancellationToken ct)
    {
        logger.LogWarning("Impersonation token issued: {Actor} acts as {Target} through client {ClientId} until {ExpiresAt:o}.",
            actor.Id, target.Id, Sanitize(callerClientId), expiresAt);
        return await WriteAsync(new ManagementAuditEvent
        {
            OperatorSubject = Truncate(actor.Id, 255),
            OperatorDisplayName = Truncate(actor.UserName, 255),
            Capability = ManagementCapabilities.UsersImpersonate,
            ResourceType = "user",
            ResourceId = Truncate(target.Id, 255),
            AuthorizationOutcome = "allowed",
            OperationOutcome = "issued",
            AfterJson = JsonSerializer.Serialize(new
            {
                client = callerClientId,
                target = target.UserName,
                scopes,
                expires_at = expiresAt.ToUnixTimeSeconds(),
            }),
        }, ct);
    }

    private async Task<bool> WriteAsync(ManagementAuditEvent audit, CancellationToken ct)
    {
        audit.OccurredAtUtc = DateTime.UtcNow;
        audit.ExpiresAtUtc = ManagementAuditRetention.Never;
        audit.CorrelationId = Truncate(httpContextAccessor.HttpContext?.TraceIdentifier ?? Guid.NewGuid().ToString("N"), 100);
        try
        {
            database.ManagementAuditEvents.Add(audit);
            await database.SaveChangesAsync(ct);
            return true;
        }
        catch (Exception exception) when (exception is not OperationCanceledException)
        {
            database.ChangeTracker.Clear();
            logger.LogError(exception, "Impersonation audit row could not be written.");
            return false;
        }
    }

    [return: System.Diagnostics.CodeAnalysis.NotNullIfNotNull(nameof(value))]
    private static string? Truncate(string? value, int max) => value is null ? null : value.Length <= max ? value : value[..max];
    private static string Sanitize(string? value) => (value ?? "none").Replace('\r', ' ').Replace('\n', ' ');
}
