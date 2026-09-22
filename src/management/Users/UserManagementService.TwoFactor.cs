using System.Globalization;
using System.Text.Json;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging;
using Sufficit.Identity.Application.Security;
using Sufficit.Identity.Core.Services;
using Sufficit.Identity.Management.Audit;
using Sufficit.Identity.Management.Authorization;

namespace Sufficit.Identity.Management.Users;

internal sealed partial class UserManagementService
{
    private async Task<ManagementAuthorizationDecision> EvaluateResetTwoFactorAsync(
        string id, ManagementRequestContext context, CancellationToken cancellationToken)
    {
        if (string.Equals(id, context.OperatorSubject, StringComparison.Ordinal))
            return ManagementAuthorizationDecision.Denied("user_self_mfa_reset_not_allowed");

        var decision = await authorization.EvaluateAsync(context.Operator,
            ManagementCapabilities.UsersResetMfa,
            new ManagementResource(ManagementResourceTypes.User, id), cancellationToken);
        if (!decision.IsAllowed) return decision;
        var readDecision = await authorization.EvaluateAsync(context.Operator,
            ManagementCapabilities.UsersRead,
            new ManagementResource(ManagementResourceTypes.User, id), cancellationToken);
        if (!readDecision.IsAllowed) return readDecision;

        // A human recovery decision always needs fresh MFA, even if a deployment
        // relaxes the general Management gate or grants a machine an exemption.
        var now = DateTimeOffset.UtcNow.ToUnixTimeSeconds();
        if (context.Operator.Identity?.IsAuthenticated != true
            || !MfaEvidencePolicy.HasMfaEvidence(context.Operator)
            || MfaEvidencePolicy.IsSecondFactorRemembered(context.Operator)
            || !long.TryParse(context.Operator.FindFirst("auth_time")?.Value,
                NumberStyles.Integer, CultureInfo.InvariantCulture, out var authenticatedAt)
            || authenticatedAt > now + 60 || authenticatedAt < now - 15 * 60)
            return ManagementAuthorizationDecision.StepUpRequired(
                "fresh_mfa_required", ManagementCapabilities.UsersResetMfa);

        return decision;
    }

    public async Task<ManagementMfaResetResult> ResetTwoFactorAsync(
        string id, ResetManagementUserTwoFactorCommand command,
        ManagementRequestContext context, CancellationToken cancellationToken = default)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(id);
        ArgumentNullException.ThrowIfNull(command);
        var resource = new ManagementResource(ManagementResourceTypes.User, id);
        var decision = await EvaluateResetTwoFactorAsync(id, context, cancellationToken);
        if (!decision.IsAllowed)
        {
            await TryWriteAuditAsync(context, ManagementCapabilities.UsersResetMfa,
                resource, decision, "denied", decision.ReasonCode, cancellationToken);
            throw new ManagementAccessException(decision);
        }

        var reason = Required(command.Reason, "user_mfa_reset_reason_required",
            "Informe o motivo da redefinição.", "reason");
        if (reason.Length is < 10 or > 500)
            throw new ManagementValidationException("user_mfa_reset_reason_invalid",
                "Descreva o motivo em 10 a 500 caracteres, sem senhas ou códigos.", "reason");
        if (!command.IdentityVerified)
            throw new ManagementValidationException("user_mfa_reset_verification_required",
                "Confirme a verificação da identidade do titular antes de continuar.", "identityVerified");

        var user = await userManager.FindByIdAsync(id)
            ?? throw new ManagementNotFoundException("user_not_found", "The user was not found.");
        var confirmation = user.UserName ?? user.Email ?? user.Id;
        if (!string.Equals(command.Confirmation?.Trim(), confirmation, StringComparison.Ordinal))
            throw new ManagementValidationException("user_mfa_reset_confirmation_invalid",
                "Digite a identificação da conta exatamente como exibida.", "confirmation");
        if (!user.TwoFactorEnabled)
            throw new ManagementConflictException("user_mfa_not_enabled",
                "A autenticação de dois fatores não está ativa. Atualize a página.");

        await using var transaction = await database.Database.BeginTransactionAsync(cancellationToken);
        try
        {
            EnsureMfaResetSucceeded(await userManager.SetTwoFactorEnabledAsync(user, false));
            EnsureMfaResetSucceeded(await userManager.ResetAuthenticatorKeyAsync(user));
            // Identity retains recovery codes when the key changes. Revoke them
            // explicitly so none can survive into the new enrollment.
            if (await userManager.GenerateNewTwoFactorRecoveryCodesAsync(user, 0) is null)
                throw new InvalidOperationException("Recovery codes could not be revoked.");
            EnsureMfaResetSucceeded(await MfaRecoveryState.RequireAsync(userManager, user));
            EnsureMfaResetSucceeded(await userManager.UpdateSecurityStampAsync(user));
            var revoked = await sessionRevoker.RevokeAsync(id, cancellationToken);
            var audit = ManagementAuditEventFactory.Create(context,
                ManagementCapabilities.UsersResetMfa, resource, decision,
                "succeeded", "user_mfa_reset");
            audit.BeforeJson = JsonSerializer.Serialize(new { TwoFactorEnabled = true });
            audit.AfterJson = JsonSerializer.Serialize(new
            {
                TwoFactorEnabled = false, ReenrollmentRequired = true,
                Reason = reason, IdentityVerified = true,
                revoked.RevokedTokens, revoked.RevokedAuthorizations, revoked.RevokedBrowserSessions,
            });
            database.ManagementAuditEvents.Add(audit);
            await database.SaveChangesAsync(cancellationToken);
            await transaction.CommitAsync(cancellationToken);
        }
        catch (Exception exception)
        {
            await transaction.RollbackAsync(CancellationToken.None);
            await transaction.DisposeAsync();
            // Do not accidentally flush the failed mutation when recording failure.
            database.ChangeTracker.Clear();
            logger.LogError(exception, "Administrative MFA reset failed. User={UserId}; Correlation={CorrelationId}", id, context.CorrelationId);
            await TryWriteAuditAsync(context, ManagementCapabilities.UsersResetMfa,
                resource, decision, "failed", "user_mfa_reset_failed", CancellationToken.None);
            throw new ManagementConflictException("user_mfa_reset_failed",
                "Não foi possível redefinir a autenticação. Nenhuma alteração foi confirmada.");
        }

        // Delivery is after commit. A transport failure must never disguise a
        // committed reset as a failed mutation and invite blind retries.
        var notificationQueued = false;
        if (user.EmailConfirmed && !string.IsNullOrWhiteSpace(user.Email))
        {
            try
            {
                await emailSender.SendEmailAsync(user.Email,
                    "Autenticação de dois fatores redefinida",
                    "<p>A autenticação de dois fatores da sua conta foi redefinida por um gestor.</p>"
                    + "<p>O autenticador anterior e os códigos de recuperação foram invalidados, e os acessos anteriores foram revogados.</p>"
                    + "<p>Entre pelo endereço habitual do serviço e configure o autenticador no novo aparelho. Guarde os novos códigos de recuperação.</p>"
                    + "<p>Se você não solicitou esta alteração, contate imediatamente o suporte pelo canal habitual.</p>");
                notificationQueued = true;
            }
            catch (Exception exception)
            {
                logger.LogError(exception, "MFA reset committed but notification failed. User={UserId}; Correlation={CorrelationId}", id, context.CorrelationId);
            }
        }
        await TryWriteAuditAsync(context, ManagementCapabilities.UsersResetMfa, resource,
            decision, notificationQueued ? "succeeded" : "failed",
            notificationQueued ? "user_mfa_reset_notification_queued" : "user_mfa_reset_notification_failed",
            CancellationToken.None);
        try
        {
            await securityEvents.CredentialChangedAsync(id, null,
                new CaepCredentialChange(CaepCredentialType.Otp, CaepChangeOperation.Deleted), CancellationToken.None);
        }
        catch (Exception exception)
        {
            logger.LogError(exception, "MFA reset committed but security event delivery failed. User={UserId}", id);
        }
        return new ManagementMfaResetResult(await GetAsync(id, context, CancellationToken.None), notificationQueued);
    }

    private static void EnsureMfaResetSucceeded(IdentityResult result)
    {
        if (!result.Succeeded) throw new IdentityAccountLifecycleException(result);
    }
}
