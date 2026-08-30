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

internal sealed partial class UserManagementService
{
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
