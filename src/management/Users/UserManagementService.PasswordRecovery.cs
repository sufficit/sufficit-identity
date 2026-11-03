using Microsoft.Extensions.Logging;
using Sufficit.Identity.Application.Accounts;
using Sufficit.Identity.Management.Authorization;

namespace Sufficit.Identity.Management.Users;

internal sealed partial class UserManagementService
{
    public async Task RequestPasswordResetAsync(string id, ManagementRequestContext context,
        CancellationToken cancellationToken = default)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(id);
        var resource = new ManagementResource(ManagementResourceTypes.User, id);
        var (capability, decision) = await EvaluatePasswordRecoveryAsync(context, resource, cancellationToken);
        if (!decision.IsAllowed)
        {
            await WriteAuditAsync(context, capability, resource, decision, "denied", decision.ReasonCode, cancellationToken);
            throw new ManagementAccessException(decision);
        }
        AccountPasswordResetDispatch dispatch;
        try
        {
            dispatch = await accountOnboarding.SendPasswordResetAsync(id, cancellationToken);
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            logger.LogError(ex, "Password recovery dispatch failed. CorrelationId={CorrelationId}", context.CorrelationId);
            dispatch = AccountPasswordResetDispatch.Failed;
        }
        var (outcome, reason) = dispatch switch
        {
            AccountPasswordResetDispatch.Sent => ("succeeded", "user_password_recovery_queued"),
            AccountPasswordResetDispatch.NotFound => ("failed", "user_not_found"),
            AccountPasswordResetDispatch.MissingEmail => ("skipped", "user_email_missing"),
            AccountPasswordResetDispatch.EmailUnconfirmed => ("skipped", "user_email_unconfirmed"),
            _ => ("failed", "user_password_recovery_failed")
        };
        await TryWriteAuditAsync(context, capability, resource, decision,
            outcome, reason, cancellationToken);
        if (dispatch == AccountPasswordResetDispatch.Sent) return;
        if (dispatch == AccountPasswordResetDispatch.NotFound)
            throw new ManagementNotFoundException(reason, "The user was not found.");
        throw new ManagementConflictException(reason, dispatch switch
        {
            AccountPasswordResetDispatch.MissingEmail => "The user has no email address.",
            AccountPasswordResetDispatch.EmailUnconfirmed => "Confirm the user's email before requesting password recovery.",
            _ => "The password recovery email could not be queued."
        });
    }

    /// <summary>
    /// The narrow capability first, then the one that can also set a password.
    /// A refusal names the narrow capability, unless the operator holds the
    /// other one and only lacks a second factor.
    /// </summary>
    private async Task<(string Capability, ManagementAuthorizationDecision Decision)> EvaluatePasswordRecoveryAsync(
        ManagementRequestContext context, ManagementResource resource, CancellationToken cancellationToken)
    {
        var recovery = await authorization.EvaluateAsync(
            context.Operator, ManagementCapabilities.UsersRecovery, resource, cancellationToken);
        if (recovery.IsAllowed) return (ManagementCapabilities.UsersRecovery, recovery);
        var reset = await authorization.EvaluateAsync(
            context.Operator, ManagementCapabilities.UsersReset, resource, cancellationToken);
        return reset.IsAllowed || reset.Outcome is ManagementAuthorizationOutcome.StepUpRequired
            ? (ManagementCapabilities.UsersReset, reset)
            : (ManagementCapabilities.UsersRecovery, recovery);
    }
}
