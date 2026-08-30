using Microsoft.EntityFrameworkCore;
using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.Logging;
using Sufficit.Identity.Core.Data;
using Sufficit.Identity.Core.Entities;
using Sufficit.Identity.Core.Services;
using Sufficit.Identity.Application.Accounts;
using Sufficit.Identity.Application.Security;
using Sufficit.Identity.Management.Audit;
using System.ComponentModel.DataAnnotations;
using System.Text.Json.Serialization;
using Sufficit.Identity.Management.Authorization;

namespace Sufficit.Identity.Management.Users;

internal sealed partial class UserManagementService(
    AppDbContext database,
    UserManager<ApplicationUser> userManager,
    IManagementAuthorizationEvaluator authorization,
    IIdentityUserSessionRevoker sessionRevoker,
    IIdentityAccountLifecycleService accountLifecycle,
    IAccountOnboardingService accountOnboarding,
    ISecurityEventTrigger securityEvents,
    ILogger<UserManagementService> logger) : IUserManagementService
{

    private static decimal Median(IReadOnlyList<decimal> values)
    {
        if (values.Count == 0) return 0;
        var ordered = values.OrderBy(value => value).ToArray();
        var middle = ordered.Length / 2;
        return ordered.Length % 2 == 0
            ? (ordered[middle - 1] + ordered[middle]) / 2m
            : ordered[middle];
    }

    public async Task RequestEmailConfirmationAsync(
        string id,
        ManagementRequestContext context,
        CancellationToken cancellationToken = default)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(id);

        // F-8 (eval 2026-08-14): resending a confirmation email is an
        // outbound mail action against an arbitrary account, not a read.
        // The old implementation rode on GetAsync's identity.users.read
        // capability, so a read-only operator could trigger unlimited
        // account emails (mail-bombing vector) and the send itself produced
        // no audit row — only GetAsync's incidental user_read did, under the
        // wrong capability. This method now demands its own capability
        // (identity.users.resend_confirmation) and journals every outcome:
        // sent, skipped (no address) and failed alike.
        var auditResource = new ManagementResource(
            ManagementResourceTypes.User,
            id);
        var decision = await DemandAsync(
            context,
            ManagementCapabilities.UsersResendConfirmation,
            auditResource,
            cancellationToken);

        var user = await userManager.FindByIdAsync(id);
        if (user is null)
        {
            await TryWriteAuditAsync(
                context,
                ManagementCapabilities.UsersResendConfirmation,
                auditResource,
                decision,
                "failed",
                "user_not_found",
                cancellationToken);
            throw new ManagementNotFoundException(
                "user_not_found",
                "O usuário não foi encontrado.");
        }

        if (string.IsNullOrWhiteSpace(user.Email))
        {
            await TryWriteAuditAsync(
                context,
                ManagementCapabilities.UsersResendConfirmation,
                auditResource,
                decision,
                "skipped",
                "user_email_missing",
                cancellationToken);
            return;
        }

        try
        {
            await accountOnboarding.RequestEmailConfirmationAsync(
                user.Email,
                cancellationToken);
        }
        catch (Exception exception) when (exception is not OperationCanceledException)
        {
            logger.LogError(
                exception,
                "Unable to resend the account confirmation email. CorrelationId={CorrelationId}",
                context.CorrelationId);
            await TryWriteAuditAsync(
                context,
                ManagementCapabilities.UsersResendConfirmation,
                auditResource,
                decision,
                "failed",
                "user_confirmation_resend_failed",
                cancellationToken);
            throw new ManagementConflictException(
                "user_confirmation_resend_failed",
                "Não foi possível reenviar a confirmação de e-mail.");
        }

        await TryWriteAuditAsync(
            context,
            ManagementCapabilities.UsersResendConfirmation,
            auditResource,
            decision,
            "succeeded",
            "user_confirmation_resent",
            cancellationToken);
    }

    public async Task<ManagementUserDetail> CreateAsync(
        CreateManagementUserCommand command,
        ManagementRequestContext context,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(command);

        var userName = Required(
            command.UserName,
            "user_name_required",
            "Informe o nome de usuário.",
            "userName");
        var email = Required(
            command.Email,
            "user_email_required",
            "Informe o e-mail do usuário.",
            "email");
        if (userName.Length > 256)
        {
            throw new ManagementValidationException(
                "user_name_too_long",
                "Use no máximo 256 caracteres no nome de usuário.",
                "userName");
        }
        if (email.Length > 256)
        {
            throw new ManagementValidationException(
                "user_email_too_long",
                "Use no máximo 256 caracteres no e-mail.",
                "email");
        }
        if (!new EmailAddressAttribute().IsValid(email))
        {
            throw new ManagementValidationException(
                "user_email_invalid",
                "Informe um endereço de e-mail válido.",
                "email");
        }
        var password = Required(
            command.InitialPassword,
            "user_password_required",
            "Informe a senha inicial.",
            "initialPassword",
            trim: false);
        var collection = new ManagementResource(
            ManagementResourceTypes.UserCollection);
        var decision = await DemandAsync(
            context,
            ManagementCapabilities.UsersCreate,
            collection,
            cancellationToken);
        var user = new ApplicationUser
        {
            UserName = userName,
            Email = email,
            EmailConfirmed = false,
            LockoutEnabled = true
        };

        await using var transaction = await database.Database
            .BeginTransactionAsync(cancellationToken);
        try
        {
            var created = await userManager.CreateAsync(user, password);
            if (!created.Succeeded)
            {
                database.ManagementAuditEvents.Add(
                    ManagementAuditEventFactory.Create(
                        context,
                        ManagementCapabilities.UsersCreate,
                        collection,
                        decision,
                        "failed",
                        IdentityReasonCode(
                            created,
                            "user_create_rejected")));
                await database.SaveChangesAsync(cancellationToken);
                await transaction.CommitAsync(cancellationToken);
                ThrowIdentityFailure(created, creatingUser: true);
            }

            database.ManagementAuditEvents.Add(
                ManagementAuditEventFactory.Create(
                    context,
                    ManagementCapabilities.UsersCreate,
                    new ManagementResource(
                        ManagementResourceTypes.User,
                        user.Id),
                    decision,
                    "succeeded",
                    "user_created"));
            await database.SaveChangesAsync(cancellationToken);
            await transaction.CommitAsync(cancellationToken);
        }
        catch (ManagementValidationException)
        {
            throw;
        }
        catch (ManagementConflictException)
        {
            throw;
        }
        catch (Exception exception)
        {
            await transaction.RollbackAsync(cancellationToken);
            await transaction.DisposeAsync();
            logger.LogError(
                exception,
                "Unable to create a management user. CorrelationId={CorrelationId}",
                context.CorrelationId);
            await TryWriteAuditAsync(
                context,
                ManagementCapabilities.UsersCreate,
                collection,
                decision,
                "failed",
                "user_create_failed",
                cancellationToken);
            throw new ManagementConflictException(
                "user_create_failed",
                "Não foi possível criar o usuário.");
        }

        return await GetAsync(
            user.Id,
            context,
            cancellationToken);
    }

    public async Task<ManagementUserDetail> UpdateProfileAsync(
        string id,
        UpdateManagementUserProfileCommand command,
        ManagementRequestContext context,
        CancellationToken cancellationToken = default)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(id);
        ArgumentNullException.ThrowIfNull(command);

        var userName = Required(
            command.UserName,
            "user_name_required",
            "Informe o nome de usuário.",
            "userName");
        var email = Required(
            command.Email,
            "user_email_required",
            "Informe o e-mail do usuário.",
            "email");
        var phoneNumber = string.IsNullOrWhiteSpace(command.PhoneNumber)
            ? null
            : command.PhoneNumber.Trim();
        if (userName.Length > 256)
        {
            throw new ManagementValidationException(
                "user_name_too_long",
                "Use no máximo 256 caracteres no nome de usuário.",
                "userName");
        }
        if (email.Length > 256)
        {
            throw new ManagementValidationException(
                "user_email_too_long",
                "Use no máximo 256 caracteres no e-mail.",
                "email");
        }
        if (!new EmailAddressAttribute().IsValid(email))
        {
            throw new ManagementValidationException(
                "user_email_invalid",
                "Informe um endereço de e-mail válido.",
                "email");
        }
        if (phoneNumber?.Length > 256)
        {
            throw new ManagementValidationException(
                "user_phone_number_too_long",
                "Use no máximo 256 caracteres no telefone.",
                "phoneNumber");
        }

        var auditResource = new ManagementResource(
            ManagementResourceTypes.User,
            id);
        var decision = await DemandAsync(
            context,
            ManagementCapabilities.UsersUpdate,
            auditResource,
            cancellationToken);

        var user = await userManager.FindByIdAsync(id);
        if (user is null)
        {
            await TryWriteAuditAsync(
                context,
                ManagementCapabilities.UsersUpdate,
                auditResource,
                decision,
                "not-found",
                "user_not_found",
                cancellationToken);
            throw new ManagementNotFoundException(
                "user_not_found",
                "O usuário não foi encontrado.");
        }

        var userNameChanged = !string.Equals(
            user.UserName,
            userName,
            StringComparison.Ordinal);
        var emailChanged = !string.Equals(
            user.Email,
            email,
            StringComparison.Ordinal);
        var phoneNumberChanged = !string.Equals(
            user.PhoneNumber,
            phoneNumber,
            StringComparison.Ordinal);
        var hasChanges =
            userNameChanged || emailChanged || phoneNumberChanged;

        await using var transaction = await database.Database
            .BeginTransactionAsync(cancellationToken);
        try
        {
            if (userNameChanged)
            {
                EnsureProfileChangeSucceeded(
                    await userManager.SetUserNameAsync(user, userName));
            }

            if (emailChanged)
            {
                EnsureProfileChangeSucceeded(
                    await userManager.SetEmailAsync(user, email));
            }

            if (phoneNumberChanged)
            {
                EnsureProfileChangeSucceeded(
                    await userManager.SetPhoneNumberAsync(
                        user,
                        phoneNumber));
            }

            if (hasChanges)
            {
                EnsureProfileChangeSucceeded(
                    await userManager.UpdateSecurityStampAsync(user));
                var revokedTokens = await sessionRevoker.RevokeTokensAsync(
                    user.Id,
                    cancellationToken);
                logger.LogInformation(
                    "Revoked {TokenCount} tokens after updating management user {UserId}. Durable authorizations were preserved. CorrelationId={CorrelationId}",
                    revokedTokens,
                    user.Id,
                    context.CorrelationId);
            }

            database.ManagementAuditEvents.Add(
                ManagementAuditEventFactory.Create(
                    context,
                    ManagementCapabilities.UsersUpdate,
                    auditResource,
                    decision,
                    "succeeded",
                    hasChanges
                        ? "user_profile_updated"
                        : "user_profile_unchanged"));

            await database.SaveChangesAsync(cancellationToken);
            await transaction.CommitAsync(cancellationToken);
        }
        catch (ProfileIdentityException exception)
        {
            await transaction.RollbackAsync(CancellationToken.None);
            database.ChangeTracker.Clear();
            await TryWriteAuditAsync(
                context,
                ManagementCapabilities.UsersUpdate,
                auditResource,
                decision,
                "failed",
                IdentityReasonCode(
                    exception.Result,
                    "user_profile_update_rejected"),
                CancellationToken.None);
            throw ProfileIdentityFailure(exception.Result);
        }
        catch (OperationCanceledException)
        {
            await transaction.RollbackAsync(CancellationToken.None);
            database.ChangeTracker.Clear();
            throw;
        }
        catch (Exception exception)
        {
            await transaction.RollbackAsync(CancellationToken.None);
            database.ChangeTracker.Clear();
            logger.LogError(
                exception,
                "Unable to update a management user profile. CorrelationId={CorrelationId}",
                context.CorrelationId);
            await TryWriteAuditAsync(
                context,
                ManagementCapabilities.UsersUpdate,
                auditResource,
                decision,
                "failed",
                "user_profile_update_failed",
                CancellationToken.None);
            throw new ManagementConflictException(
                "user_profile_update_failed",
                "Não foi possível atualizar o perfil do usuário.");
        }

        return await GetAsync(
            id,
            context,
            cancellationToken);
    }

    public async Task<ManagementUserDetail> ResetPasswordAsync(
        string id,
        ResetManagementUserPasswordCommand command,
        ManagementRequestContext context,
        CancellationToken cancellationToken = default)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(id);
        ArgumentNullException.ThrowIfNull(command);

        var password = Required(
            command.NewPassword,
            "user_password_required",
            "Informe a nova senha.",
            "newPassword",
            trim: false);
        var auditResource = new ManagementResource(
            ManagementResourceTypes.User,
            id);
        var decision = await DemandAsync(
            context,
            ManagementCapabilities.UsersReset,
            auditResource,
            cancellationToken);

        var user = await userManager.FindByIdAsync(id);
        if (user is null)
        {
            await TryWriteAuditAsync(
                context,
                ManagementCapabilities.UsersReset,
                auditResource,
                decision,
                "not-found",
                "user_not_found",
                cancellationToken);
            throw new ManagementNotFoundException(
                "user_not_found",
                "O usuário não foi encontrado.");
        }

        await using var transaction = await database.Database
            .BeginTransactionAsync(cancellationToken);
        try
        {
            var token = await userManager.GeneratePasswordResetTokenAsync(user);
            var reset = await userManager.ResetPasswordAsync(
                user,
                token,
                password);
            if (!reset.Succeeded)
            {
                database.ManagementAuditEvents.Add(
                    ManagementAuditEventFactory.Create(
                        context,
                        ManagementCapabilities.UsersReset,
                        auditResource,
                        decision,
                        "failed",
                        IdentityReasonCode(
                            reset,
                            "user_password_reset_rejected")));
                await database.SaveChangesAsync(cancellationToken);
                await transaction.CommitAsync(cancellationToken);
                ThrowIdentityFailure(reset, creatingUser: false);
            }

            database.ManagementAuditEvents.Add(
                ManagementAuditEventFactory.Create(
                    context,
                    ManagementCapabilities.UsersReset,
                    auditResource,
                    decision,
                    "succeeded",
                    "user_password_reset"));

            await database.SaveChangesAsync(cancellationToken);
            await transaction.CommitAsync(cancellationToken);
        }
        catch (ManagementValidationException)
        {
            throw;
        }
        catch (Exception exception)
        {
            await transaction.RollbackAsync(cancellationToken);
            await transaction.DisposeAsync();
            logger.LogError(
                exception,
                "Unable to reset a management user password. CorrelationId={CorrelationId}",
                context.CorrelationId);
            await TryWriteAuditAsync(
                context,
                ManagementCapabilities.UsersReset,
                auditResource,
                decision,
                "failed",
                "user_password_reset_failed",
                cancellationToken);
            throw new ManagementConflictException(
                "user_password_reset_failed",
                "Não foi possível redefinir a senha do usuário.");
        }

        // CAEP credential-change: administrative password reset has no target
        // session, so the emitted SET carries an iss_sub subject only.
        await securityEvents.CredentialChangedAsync(
            id,
            null,
            new CaepCredentialChange(
                CaepCredentialType.Password,
                CaepChangeOperation.Updated),
            cancellationToken);

        return await GetAsync(
            id,
            context,
            cancellationToken);
    }

    public async Task<ManagementUserDetail> SetLockoutAsync(
        string id,
        SetManagementUserLockoutCommand command,
        ManagementRequestContext context,
        CancellationToken cancellationToken = default)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(id);
        ArgumentNullException.ThrowIfNull(command);

        var decision = await EvaluateLockoutChangeAsync(
            id,
            context,
            command.Locked,
            cancellationToken);
        var auditResource = new ManagementResource(
            ManagementResourceTypes.User,
            id);

        if (!decision.IsAllowed)
        {
            await TryWriteAuditAsync(
                context,
                ManagementCapabilities.UsersDisable,
                auditResource,
                decision,
                "denied",
                decision.ReasonCode,
                cancellationToken);
            throw new ManagementAccessException(decision);
        }

        var user = await userManager.FindByIdAsync(id);
        if (user is null)
        {
            await TryWriteAuditAsync(
                context,
                ManagementCapabilities.UsersDisable,
                auditResource,
                decision,
                "not-found",
                "user_not_found",
                cancellationToken);
            throw new ManagementNotFoundException(
                "user_not_found",
                "O usuário não foi encontrado.");
        }

        await using var transaction = await database.Database
            .BeginTransactionAsync(cancellationToken);
        try
        {
            var revocation = await accountLifecycle.SetActiveAsync(
                user,
                active: !command.Locked,
                cancellationToken);
            logger.LogInformation(
                "Revoked {TokenCount} tokens and {AuthorizationCount} authorizations for management user {UserId}. CorrelationId={CorrelationId}",
                revocation.RevokedTokens,
                revocation.RevokedAuthorizations,
                user.Id,
                context.CorrelationId);

            database.ManagementAuditEvents.Add(
                ManagementAuditEventFactory.Create(
                    context,
                    ManagementCapabilities.UsersDisable,
                    auditResource,
                    decision,
                    "succeeded",
                    command.Locked
                        ? "user_locked"
                        : "user_unlocked"));

            await database.SaveChangesAsync(cancellationToken);
            await transaction.CommitAsync(cancellationToken);
        }
        catch (OperationCanceledException)
        {
            await transaction.RollbackAsync(CancellationToken.None);
            database.ChangeTracker.Clear();
            throw;
        }
        catch (Exception exception)
        {
            await transaction.RollbackAsync(CancellationToken.None);
            // UserManager and the OpenIddict managers share this scoped
            // DbContext. After rollback their tracked mutations must be
            // discarded before the failure audit is saved, otherwise the
            // audit SaveChanges could accidentally reapply the lockout.
            database.ChangeTracker.Clear();
            logger.LogError(
                exception,
                "Unable to change a management user lockout. CorrelationId={CorrelationId}",
                context.CorrelationId);
            await TryWriteAuditAsync(
                context,
                ManagementCapabilities.UsersDisable,
                auditResource,
                decision,
                "failed",
                command.Locked
                    ? "user_lock_failed"
                    : "user_unlock_failed",
                cancellationToken);
            throw new ManagementConflictException(
                command.Locked
                    ? "user_lock_failed"
                    : "user_unlock_failed",
                command.Locked
                    ? "Não foi possível bloquear o acesso do usuário."
                    : "Não foi possível desbloquear o acesso do usuário.");
        }

        return await GetAsync(
            id,
            context,
            cancellationToken);
    }

    public async Task DeleteAsync(
        string id,
        ManagementRequestContext context,
        CancellationToken cancellationToken = default)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(id);

        var auditResource = new ManagementResource(
            ManagementResourceTypes.User,
            id);
        var decision = await EvaluateDeleteAsync(
            id,
            context,
            cancellationToken);
        if (!decision.IsAllowed)
        {
            await TryWriteAuditAsync(
                context,
                ManagementCapabilities.UsersDelete,
                auditResource,
                decision,
                "denied",
                decision.ReasonCode,
                cancellationToken);
            throw new ManagementAccessException(decision);
        }

        var user = await userManager.FindByIdAsync(id);
        if (user is null)
        {
            await TryWriteAuditAsync(
                context,
                ManagementCapabilities.UsersDelete,
                auditResource,
                decision,
                "not-found",
                "user_not_found",
                cancellationToken);
            throw new ManagementNotFoundException(
                "user_not_found",
                "O usuário não foi encontrado.");
        }

        await using var transaction = await database.Database
            .BeginTransactionAsync(cancellationToken);
        try
        {
            var revocation = await accountLifecycle.DeleteAsync(
                user,
                cancellationToken);

            database.ManagementAuditEvents.Add(
                ManagementAuditEventFactory.Create(
                    context,
                    ManagementCapabilities.UsersDelete,
                    auditResource,
                    decision,
                    "succeeded",
                    "user_deleted"));
            await database.SaveChangesAsync(cancellationToken);
            await transaction.CommitAsync(cancellationToken);

            logger.LogInformation(
                "Deleted identity user {UserId} after revoking {TokenCount} tokens and {AuthorizationCount} authorizations. CorrelationId={CorrelationId}",
                user.Id,
                revocation.RevokedTokens,
                revocation.RevokedAuthorizations,
                context.CorrelationId);
        }
        catch (OperationCanceledException)
        {
            await transaction.RollbackAsync(CancellationToken.None);
            database.ChangeTracker.Clear();
            throw;
        }
        catch (Exception exception)
        {
            await transaction.RollbackAsync(CancellationToken.None);
            database.ChangeTracker.Clear();
            logger.LogError(
                exception,
                "Unable to delete a management user. CorrelationId={CorrelationId}",
                context.CorrelationId);
            await TryWriteAuditAsync(
                context,
                ManagementCapabilities.UsersDelete,
                auditResource,
                decision,
                "failed",
                "user_delete_failed",
                CancellationToken.None);
            throw new ManagementConflictException(
                "user_delete_failed",
                "Não foi possível excluir o usuário.");
        }
    }

    private async Task<ManagementAuthorizationDecision>
        EvaluateLockoutChangeAsync(
            string userId,
            ManagementRequestContext context,
            bool locking,
            CancellationToken cancellationToken)
    {
        if (locking
            && string.Equals(
                userId,
                context.OperatorSubject,
                StringComparison.Ordinal))
        {
            return ManagementAuthorizationDecision.Denied(
                "user_self_lockout_not_allowed");
        }

        return await authorization.EvaluateAsync(
            context.Operator,
            ManagementCapabilities.UsersDisable,
            new ManagementResource(
                ManagementResourceTypes.User,
                userId),
            cancellationToken);
    }

    private async Task<ManagementAuthorizationDecision> EvaluateDeleteAsync(
        string userId,
        ManagementRequestContext context,
        CancellationToken cancellationToken)
    {
        if (string.Equals(
            userId,
            context.OperatorSubject,
            StringComparison.Ordinal))
        {
            return ManagementAuthorizationDecision.Denied(
                "user_self_delete_not_allowed");
        }

        return await authorization.EvaluateAsync(
            context.Operator,
            ManagementCapabilities.UsersDelete,
            new ManagementResource(
                ManagementResourceTypes.User,
                userId),
            cancellationToken);
    }

    private static ManagementUserActions Actions(
        ManagementAuthorizationDecision resetDecision,
        ManagementAuthorizationDecision lockoutDecision,
        ManagementAuthorizationDecision updateProfileDecision,
        ManagementAuthorizationDecision deleteDecision) =>
        new(
            resetDecision.IsAllowed,
            resetDecision.Outcome is
                ManagementAuthorizationOutcome.StepUpRequired,
            resetDecision.ReasonCode,
            lockoutDecision.IsAllowed,
            lockoutDecision.Outcome is
                ManagementAuthorizationOutcome.StepUpRequired,
            lockoutDecision.ReasonCode,
            updateProfileDecision.IsAllowed,
            updateProfileDecision.Outcome is
                ManagementAuthorizationOutcome.StepUpRequired,
            updateProfileDecision.ReasonCode,
            deleteDecision.IsAllowed,
            deleteDecision.Outcome is
                ManagementAuthorizationOutcome.StepUpRequired,
            deleteDecision.ReasonCode);

    private static string Required(
        string? value,
        string reasonCode,
        string message,
        string field,
        bool trim = true)
    {
        if (string.IsNullOrWhiteSpace(value))
        {
            throw new ManagementValidationException(
                reasonCode,
                message,
                field);
        }

        return trim ? value.Trim() : value;
    }

}
