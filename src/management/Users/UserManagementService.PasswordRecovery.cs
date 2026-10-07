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
        var decision = await DemandAsync(context, ManagementCapabilities.UsersReset, resource, cancellationToken);
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
        await TryWriteAuditAsync(context, ManagementCapabilities.UsersReset, resource, decision,
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
}
