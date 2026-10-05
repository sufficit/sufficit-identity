using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.Logging;
using Sufficit.Identity.Application.Security;
using Sufficit.Identity.Management.Audit;
using Sufficit.Identity.Management.Authorization;

namespace Sufficit.Identity.Management.Users;

internal sealed partial class UserManagementService
{
    public async Task<ManagementUserExternalLogins> GetExternalLoginsAsync(
        string id,
        ManagementRequestContext context,
        CancellationToken cancellationToken = default)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(id);

        var resource = new ManagementResource(
            ManagementResourceTypes.User,
            id);
        var decision = await DemandAsync(
            context,
            ManagementCapabilities.UsersRead,
            resource,
            cancellationToken);

        var user = await userManager.FindByIdAsync(id);
        if (user is null)
        {
            await WriteAuditAsync(
                context,
                ManagementCapabilities.UsersRead,
                resource,
                decision,
                "not-found",
                "user_not_found",
                cancellationToken);
            throw new ManagementNotFoundException(
                "user_not_found",
                "The user was not found.");
        }

        var logins = await userManager.GetLoginsAsync(user);
        var hasPassword = await userManager.HasPasswordAsync(user);
        var removeDecision = await authorization.EvaluateAsync(
            context.Operator,
            ManagementCapabilities.UsersReset,
            resource,
            cancellationToken);

        await WriteAuditAsync(
            context,
            ManagementCapabilities.UsersRead,
            resource,
            decision,
            "succeeded",
            "user_external_logins_read",
            cancellationToken);

        return new ManagementUserExternalLogins(
            user.Id,
            user.UserName,
            user.Email,
            logins
                .OrderBy(login => login.LoginProvider, StringComparer.Ordinal)
                .Select(login => new ManagementUserExternalLogin(
                    login.LoginProvider,
                    login.ProviderKey,
                    login.ProviderDisplayName))
                .ToArray(),
            hasPassword,
            removeDecision.IsAllowed,
            removeDecision.Outcome is ManagementAuthorizationOutcome.StepUpRequired,
            removeDecision.ReasonCode);
    }

    public async Task<ManagementUserExternalLogins> RemoveExternalLoginAsync(
        string id,
        RemoveManagementUserExternalLoginCommand command,
        ManagementRequestContext context,
        CancellationToken cancellationToken = default)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(id);
        ArgumentNullException.ThrowIfNull(command);

        var provider = Required(
            command.LoginProvider,
            "user_external_login_provider_required",
            "Provide the external login provider.",
            "loginProvider",
            trim: true);
        var providerKey = Required(
            command.ProviderKey,
            "user_external_login_key_required",
            "Provide the external login key.",
            "providerKey",
            trim: false);
        var resource = new ManagementResource(
            ManagementResourceTypes.User,
            id);
        var decision = await DemandAsync(
            context,
            ManagementCapabilities.UsersReset,
            resource,
            cancellationToken);

        var user = await userManager.FindByIdAsync(id);
        if (user is null)
        {
            await TryWriteAuditAsync(
                context,
                ManagementCapabilities.UsersReset,
                resource,
                decision,
                "not-found",
                "user_not_found",
                cancellationToken);
            throw new ManagementNotFoundException(
                "user_not_found",
                "The user was not found.");
        }

        var login = (await userManager.GetLoginsAsync(user)).FirstOrDefault(candidate =>
            string.Equals(candidate.LoginProvider, provider, StringComparison.Ordinal)
            && string.Equals(candidate.ProviderKey, providerKey, StringComparison.Ordinal));
        if (login is null)
        {
            await TryWriteAuditAsync(
                context,
                ManagementCapabilities.UsersReset,
                resource,
                decision,
                "not-found",
                "user_external_login_not_found",
                cancellationToken);
            throw new ManagementNotFoundException(
                "user_external_login_not_found",
                "The external login was not found.");
        }

        // RemoveLoginAsync rotates the security stamp, so sessions that were
        // established through the removed identity stop validating.
        var removal = await userManager.RemoveLoginAsync(
            user,
            login.LoginProvider,
            login.ProviderKey);
        if (!removal.Succeeded)
        {
            logger.LogWarning(
                "Unable to remove external login {Provider} from user {UserId}: {Codes}. CorrelationId={CorrelationId}",
                login.LoginProvider,
                user.Id,
                string.Join(',', removal.Errors.Select(error => error.Code)),
                context.CorrelationId);
            await TryWriteAuditAsync(
                context,
                ManagementCapabilities.UsersReset,
                resource,
                decision,
                "failed",
                "user_external_login_remove_failed",
                cancellationToken);
            throw new ManagementConflictException(
                "user_external_login_remove_failed",
                "The external login could not be removed.");
        }

        await TryWriteAuditAsync(
            context,
            ManagementCapabilities.UsersReset,
            resource,
            decision,
            "succeeded",
            "user_external_login_removed",
            cancellationToken);
        logger.LogInformation(
            "Operator removed external login {Provider} from user {UserId}. CorrelationId={CorrelationId}",
            login.LoginProvider,
            user.Id,
            context.CorrelationId);

        await securityEvents.CredentialChangedAsync(
            user.Id,
            null,
            new CaepCredentialChange(
                CaepCredentialType.Federated,
                CaepChangeOperation.Deleted,
                FederatedType: login.LoginProvider),
            cancellationToken);

        return await GetExternalLoginsAsync(
            id,
            context,
            cancellationToken);
    }
}
