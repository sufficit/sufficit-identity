using Sufficit.Identity.Management.Users;
using Sufficit.Identity.Management.Authorization;

namespace Sufficit.Identity.Tests;

public sealed partial class ManagementUiRoutingTests
{
    private sealed class StubUserManagementService : IUserManagementService
    {
        private static readonly ManagementUserSummary Summary = new(
            "user-1",
            "alice",
            "alice@tests.local",
            EmailConfirmed: true,
            TwoFactorEnabled: true,
            IsLockedOut: false);

        public Task<ManagementUserAccess> GetAccessAsync(
            ManagementRequestContext context,
            CancellationToken cancellationToken = default) =>
            Task.FromResult(new ManagementUserAccess(true, true));

        public Task<ManagementUserPage> SearchAsync(
            ManagementUserSearch query,
            ManagementRequestContext context,
            CancellationToken cancellationToken = default) =>
            Task.FromResult(new ManagementUserPage(
                [Summary],
                1,
                25,
                1,
                new ManagementUserAnalytics(
                    DirectoryTotal: 2_525,
                    MatchingTotal: 1,
                    RegisteredToday: 3,
                    TypicalRegistrationsPerDay: 2,
                    AnomalyThreshold: 11,
                    Days:
                    [
                        new(new DateOnly(2026, 8, 3), 12, IsAnomaly: true),
                        new(new DateOnly(2026, 8, 4), 14, IsAnomaly: true),
                        new(new DateOnly(2026, 8, 5), 18, IsAnomaly: true),
                        new(new DateOnly(2026, 8, 6), 13, IsAnomaly: true)
                    ])));

        public Task<ManagementUserDetail> GetAsync(
            string id,
            ManagementRequestContext context,
            CancellationToken cancellationToken = default) =>
            Task.FromResult(new ManagementUserDetail(
                Summary.Id,
                Summary.UserName,
                Summary.Email,
                Summary.EmailConfirmed,
                null,
                false,
                Summary.TwoFactorEnabled,
                true,
                null,
                0,
                DateTime.UtcNow,
                new ManagementUserActions(
                    CanResetPassword: true,
                    ResetPasswordRequiresMfa: false,
                    ResetPasswordReasonCode: "allowed",
                    CanSetLockout: true,
                    SetLockoutRequiresMfa: false,
                    SetLockoutReasonCode: "allowed",
                    CanUpdateProfile: true,
                    UpdateProfileRequiresMfa: false,
                    UpdateProfileReasonCode: "allowed",
                    CanDelete: true,
                    DeleteRequiresMfa: false,
                    DeleteReasonCode: "allowed",
                    CanResetTwoFactor: true,
                    ResetTwoFactorReasonCode: "allowed")));

        public Task<ManagementUserDetail> CreateAsync(
            CreateManagementUserCommand command,
            ManagementRequestContext context,
            CancellationToken cancellationToken = default) =>
            throw new NotSupportedException();

        public Task<ManagementUserDetail> UpdateProfileAsync(
            string id,
            UpdateManagementUserProfileCommand command,
            ManagementRequestContext context,
            CancellationToken cancellationToken = default) =>
            throw new NotSupportedException();

        public Task<ManagementUserDetail> ResetPasswordAsync(
            string id,
            ResetManagementUserPasswordCommand command,
            ManagementRequestContext context,
            CancellationToken cancellationToken = default) =>
            throw new NotSupportedException();

        public async Task<ManagementMfaResetResult> ResetTwoFactorAsync(
            string id, ResetManagementUserTwoFactorCommand command, ManagementRequestContext context, CancellationToken cancellationToken = default)
        {
            if (!command.IdentityVerified || command.Confirmation != "alice" || command.Reason.Length < 10)
                throw new ManagementValidationException("user_mfa_reset_confirmation_invalid", "Invalid confirmation.");
            var user = await GetAsync(id, context, cancellationToken);
            return new(user with { TwoFactorEnabled = false, TwoFactorReenrollmentRequired = true }, NotificationQueued: true);
        }

        public Task<ManagementUserDetail> SetLockoutAsync(
            string id,
            SetManagementUserLockoutCommand command,
            ManagementRequestContext context,
            CancellationToken cancellationToken = default) =>
            throw new NotSupportedException();

        public Task RequestEmailConfirmationAsync(
            string id,
            ManagementRequestContext context,
            CancellationToken cancellationToken = default) =>
            throw new NotSupportedException();

        public Task DeleteAsync(
            string id,
            ManagementRequestContext context,
            CancellationToken cancellationToken = default) =>
            throw new NotSupportedException();
    }

}
