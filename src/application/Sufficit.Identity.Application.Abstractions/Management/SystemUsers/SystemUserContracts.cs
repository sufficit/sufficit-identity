using Sufficit.Identity.Management.Authorization;

namespace Sufficit.Identity.Management.SystemUsers;

/// <summary>Protocol names of the system-user enrollment, shared by the STS and Management.</summary>
public static class SystemUserEnrollmentProtocol
{
    /// <summary>
    /// Extension grant (RFC 6749 §4.5) that redeems an operator-issued,
    /// one-time enrollment code for a system user's long-lived credential.
    /// </summary>
    public const string GrantType = "urn:sufficit:params:oauth:grant-type:system-user-enrollment";

    /// <summary>Token request parameter carrying the code.</summary>
    public const string CodeParameter = "enrollment_code";
}

/// <summary>
/// A system user: an ordinary user to every application that never signs in
/// interactively. Its credentials come from one-time enrollment codes.
/// </summary>
public sealed record SystemUserSummary(
    string UserId,
    string UserName,
    string? DisplayName,
    string CreatedBy,
    DateTime CreatedAtUtc,
    bool Disabled,
    DateTime? DisabledAtUtc,
    int ActiveCredentials);

/// <summary>
/// Creates a system user. It has no password, e-mail or external login.
/// <paramref name="UserId"/> lets the caller reuse an ID it already owns (for
/// example its own record of the agent); empty means a new one.
/// </summary>
public sealed record CreateSystemUserCommand(
    string UserName,
    string? DisplayName = null,
    Guid? UserId = null);

/// <summary>Status of an enrollment code, from the operator's point of view.</summary>
public static class SystemUserEnrollmentStatus
{
    /// <summary>Issued, not yet redeemed, still within its lifetime.</summary>
    public const string Pending = "pending";

    /// <summary>Redeemed: a credential is active.</summary>
    public const string Active = "active";

    public const string Expired = "expired";

    public const string Revoked = "revoked";
}

public sealed record SystemUserEnrollmentSummary(
    Guid Id,
    string ClientId,
    string Label,
    string CodeHint,
    string IssuedBy,
    DateTime CreatedAtUtc,
    DateTime ExpiresAtUtc,
    DateTime? RedeemedAtUtc,
    DateTime? RevokedAtUtc,
    string Status);

/// <param name="ClientId">The client that will redeem the code; it must allow the enrollment grant.</param>
/// <param name="Label">Where the credential will live (host, agent), for the listing and the audit.</param>
/// <param name="LifetimeHours">How long the code can be redeemed (1–168, default 24).</param>
public sealed record IssueSystemUserEnrollmentCommand(
    string ClientId,
    string Label,
    int? LifetimeHours = null);

/// <summary>
/// The complete set of entitlements (for example <c>aiuser:&lt;context&gt;</c>) a
/// system user holds afterwards; anything not listed is removed.
/// </summary>
public sealed record SetSystemUserEntitlementsCommand(IReadOnlyList<string>? Entitlements);

/// <summary>The code is returned here once and never again.</summary>
public sealed record SystemUserEnrollmentIssueResult(
    SystemUserEnrollmentSummary Enrollment,
    string Code,
    string GrantType);

public interface ISystemUserManagementService
{
    Task<IReadOnlyList<SystemUserSummary>> ListAsync(
        ManagementRequestContext context,
        CancellationToken cancellationToken = default);

    Task<SystemUserSummary> CreateAsync(
        CreateSystemUserCommand command,
        ManagementRequestContext context,
        CancellationToken cancellationToken = default);

    /// <summary>
    /// Enables or disables; <paramref name="enabled"/> null inverts. Disabling
    /// revokes every credential and blocks new ones until re-enabled.
    /// </summary>
    Task<SystemUserSummary> ToggleAsync(
        string userId,
        bool? enabled,
        ManagementRequestContext context,
        CancellationToken cancellationToken = default);

    Task<IReadOnlyList<string>> GetEntitlementsAsync(
        string userId,
        ManagementRequestContext context,
        CancellationToken cancellationToken = default);

    /// <summary>Replaces the system user's entitlements; contexts are stored compact (32 hex).</summary>
    Task<IReadOnlyList<string>> SetEntitlementsAsync(
        string userId,
        SetSystemUserEntitlementsCommand command,
        ManagementRequestContext context,
        CancellationToken cancellationToken = default);

    Task<IReadOnlyList<SystemUserEnrollmentSummary>> ListEnrollmentsAsync(
        string userId,
        ManagementRequestContext context,
        CancellationToken cancellationToken = default);

    Task<SystemUserEnrollmentIssueResult> IssueEnrollmentAsync(
        string userId,
        IssueSystemUserEnrollmentCommand command,
        ManagementRequestContext context,
        CancellationToken cancellationToken = default);

    /// <summary>Revokes the code, and the credential when it was already redeemed.</summary>
    Task RevokeEnrollmentAsync(
        string userId,
        Guid enrollmentId,
        ManagementRequestContext context,
        CancellationToken cancellationToken = default);
}
