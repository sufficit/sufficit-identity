using System.ComponentModel.DataAnnotations;
using System.Text.Json.Serialization;
using Sufficit.Identity.Management.Authorization;

namespace Sufficit.Identity.Management.Users;

/// <summary>
/// Canonical application boundary for identity-account administration.
/// Both embedded UI and HTTP adapters execute these same use cases.
/// </summary>
public interface IUserManagementService
{
    Task<ManagementUserAccess> GetAccessAsync(
        ManagementRequestContext context,
        CancellationToken cancellationToken = default);

    Task<ManagementUserPage> SearchAsync(
        ManagementUserSearch query,
        ManagementRequestContext context,
        CancellationToken cancellationToken = default);

    Task<ManagementUserDetail> GetAsync(
        string id,
        ManagementRequestContext context,
        CancellationToken cancellationToken = default);

    Task<ManagementUserDetail> CreateAsync(
        CreateManagementUserCommand command,
        ManagementRequestContext context,
        CancellationToken cancellationToken = default);

    Task<ManagementUserDetail> UpdateProfileAsync(
        string id,
        UpdateManagementUserProfileCommand command,
        ManagementRequestContext context,
        CancellationToken cancellationToken = default);

    Task<ManagementUserDetail> ResetPasswordAsync(
        string id,
        ResetManagementUserPasswordCommand command,
        ManagementRequestContext context,
        CancellationToken cancellationToken = default);

    Task<ManagementUserDetail> SetLockoutAsync(
        string id,
        SetManagementUserLockoutCommand command,
        ManagementRequestContext context,
        CancellationToken cancellationToken = default);

    /// <summary>
    /// Resends the account-confirmation email to the user identified by
    /// <paramref name="id"/>. Requires the dedicated
    /// <c>identity.users.resend_confirmation</c> capability (an outbound mail
    /// action, not a read) and audits every outcome — see the implementation
    /// for the F-8 rationale.
    /// </summary>
    Task RequestEmailConfirmationAsync(
        string id,
        ManagementRequestContext context,
        CancellationToken cancellationToken = default);

    Task DeleteAsync(
        string id,
        ManagementRequestContext context,
        CancellationToken cancellationToken = default);
}

public sealed record ManagementUserAccess(
    bool CanRead,
    bool CanCreate);

public sealed record CreateManagementUserCommand(
    string UserName,
    string Email,
    string InitialPassword);

public sealed record UpdateManagementUserProfileCommand(
    string UserName,
    string Email,
    string? PhoneNumber);

public sealed record ResetManagementUserPasswordCommand(
    string NewPassword);

public sealed record SetManagementUserLockoutCommand(
    bool Locked);

public sealed record ManagementUserSearch(
    string? Search = null,
    int Page = 1,
    int PageSize = 25,
    DateOnly? RegisteredFrom = null,
    DateOnly? RegisteredTo = null,
    DateOnly? RegisteredOn = null,
    ManagementUserStateFilter State = ManagementUserStateFilter.All,
    ManagementUserBooleanFilter EmailConfirmed = ManagementUserBooleanFilter.All,
    ManagementUserBooleanFilter Mfa = ManagementUserBooleanFilter.All,
    ManagementUserSort Sort = ManagementUserSort.CreatedNewest,
    int AnalyticsDays = 30,
    ManagementUserReviewFilter Review = ManagementUserReviewFilter.All);

public enum ManagementUserStateFilter
{
    All,
    Active,
    Locked,
}

public enum ManagementUserBooleanFilter
{
    All,
    Enabled,
    Disabled,
}

public enum ManagementUserSort
{
    CreatedNewest,
    CreatedOldest,
    NameAscending,
    NameDescending,
    EmailAscending,
    EmailDescending,
}

public enum ManagementUserReviewFilter
{
    All,
    StaleUnverifiedWithoutExternal,
}

public sealed record ManagementUserPage(
    IReadOnlyList<ManagementUserSummary> Items,
    int Page,
    int PageSize,
    int TotalCount,
    ManagementUserAnalytics? Analytics = null);

public sealed record ManagementUserAnalytics(
    int DirectoryTotal,
    int MatchingTotal,
    int RegisteredToday,
    decimal TypicalRegistrationsPerDay,
    int AnomalyThreshold,
    IReadOnlyList<ManagementUserRegistrationDay> Days,
    int StaleUnverifiedWithoutExternalTotal = 0);

public sealed record ManagementUserRegistrationDay(
    DateOnly Date,
    int Count,
    bool IsAnomaly);

public sealed record ManagementUserSummary(
    string Id,
    string? UserName,
    string? Email,
    bool EmailConfirmed,
    bool TwoFactorEnabled,
    bool IsLockedOut,
    DateTime CreatedAtUtc = default,
    bool HasExternalLogin = false);

public sealed record ManagementUserActions(
    bool CanResetPassword,
    bool ResetPasswordRequiresMfa,
    string ResetPasswordReasonCode,
    bool CanSetLockout = false,
    bool SetLockoutRequiresMfa = false,
    string SetLockoutReasonCode = "not_evaluated",
    bool CanUpdateProfile = false,
    bool UpdateProfileRequiresMfa = false,
    string UpdateProfileReasonCode = "not_evaluated",
    bool CanDelete = false,
    bool DeleteRequiresMfa = false,
    string DeleteReasonCode = "not_evaluated");

[method: JsonConstructor]
public sealed record ManagementUserDetail(
    string Id,
    string? UserName,
    string? Email,
    bool EmailConfirmed,
    string? PhoneNumber,
    bool PhoneNumberConfirmed,
    bool TwoFactorEnabled,
    bool LockoutEnabled,
    DateTimeOffset? LockoutEnd,
    int AccessFailedCount,
    DateTime UpdatedAt,
    ManagementUserActions Actions)
{
    public ManagementUserDetail(
        string id,
        string? userName,
        string? email,
        bool emailConfirmed,
        string? phoneNumber,
        bool phoneNumberConfirmed,
        bool twoFactorEnabled,
        bool lockoutEnabled,
        DateTimeOffset? lockoutEnd,
        int accessFailedCount,
        DateTime updatedAt)
        : this(
            id,
            userName,
            email,
            emailConfirmed,
            phoneNumber,
            phoneNumberConfirmed,
            twoFactorEnabled,
            lockoutEnabled,
            lockoutEnd,
            accessFailedCount,
            updatedAt,
            new ManagementUserActions(
                CanResetPassword: false,
                ResetPasswordRequiresMfa: false,
                ResetPasswordReasonCode: "not_evaluated"))
    {
    }
}
