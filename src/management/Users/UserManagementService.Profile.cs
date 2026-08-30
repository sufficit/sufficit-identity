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

    private static decimal Median(IReadOnlyList<decimal> values)
    {
        if (values.Count == 0) return 0;
        var ordered = values.OrderBy(value => value).ToArray();
        var middle = ordered.Length / 2;
        return ordered.Length % 2 == 0
            ? (ordered[middle - 1] + ordered[middle]) / 2m
            : ordered[middle];
    }
}
