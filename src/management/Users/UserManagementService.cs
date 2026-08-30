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

}
