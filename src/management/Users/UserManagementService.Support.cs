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
    private static void EnsureProfileChangeSucceeded(
        IdentityResult result)
    {
        if (!result.Succeeded)
        {
            throw new ProfileIdentityException(result);
        }
    }

    private static string IdentityReasonCode(
        IdentityResult result,
        string fallback) =>
        result.Errors
            .Select(error => error.Code switch
            {
                "DuplicateUserName" => "user_name_conflict",
                "DuplicateEmail" => "user_email_conflict",
                "InvalidUserName" => "user_name_invalid",
                "InvalidEmail" => "user_email_invalid",
                "InvalidToken" => "user_password_reset_token_invalid",
                var code when code.StartsWith(
                    "Password",
                    StringComparison.Ordinal) =>
                    "user_password_invalid",
                _ => fallback
            })
            .FirstOrDefault() ?? fallback;

    private static void ThrowIdentityFailure(
        IdentityResult result,
        bool creatingUser)
    {
        var reasonCode = IdentityReasonCode(
            result,
            creatingUser
                ? "user_create_rejected"
                : "user_password_reset_rejected");
        if (reasonCode is "user_name_conflict" or "user_email_conflict")
        {
            throw new ManagementConflictException(
                reasonCode,
                reasonCode == "user_name_conflict"
                    ? "Já existe um usuário com esse nome."
                    : "Já existe um usuário com esse e-mail.");
        }

        var field = reasonCode switch
        {
            "user_name_invalid" => "userName",
            "user_email_invalid" => "email",
            _ => creatingUser ? "initialPassword" : "newPassword"
        };
        var messages = result.Errors
            .Select(error => error.Code switch
            {
                "PasswordTooShort" =>
                    "A senha não possui o comprimento mínimo configurado.",
                "PasswordRequiresNonAlphanumeric" =>
                    "A senha precisa conter um caractere especial.",
                "PasswordRequiresDigit" =>
                    "A senha precisa conter um número.",
                "PasswordRequiresLower" =>
                    "A senha precisa conter uma letra minúscula.",
                "PasswordRequiresUpper" =>
                    "A senha precisa conter uma letra maiúscula.",
                "PasswordRequiresUniqueChars" =>
                    "A senha precisa conter mais caracteres diferentes.",
                "InvalidUserName" =>
                    "O nome de usuário contém caracteres não permitidos.",
                "InvalidEmail" =>
                    "Informe um endereço de e-mail válido.",
                _ => "Revise os dados informados e tente novamente."
            })
            .Distinct(StringComparer.Ordinal)
            .ToArray();

        throw new ManagementValidationException(
            reasonCode,
            string.Join(' ', messages),
            field);
    }

    private static Exception ProfileIdentityFailure(
        IdentityResult result)
    {
        var reasonCode = IdentityReasonCode(
            result,
            "user_profile_update_rejected");
        if (reasonCode is "user_name_conflict" or "user_email_conflict")
        {
            return new ManagementConflictException(
                reasonCode,
                reasonCode == "user_name_conflict"
                    ? "Já existe um usuário com esse nome."
                    : "Já existe um usuário com esse e-mail.");
        }

        var field = reasonCode switch
        {
            "user_name_invalid" => "userName",
            "user_email_invalid" => "email",
            _ => null
        };
        var message = reasonCode switch
        {
            "user_name_invalid" =>
                "O nome de usuário contém caracteres não permitidos.",
            "user_email_invalid" =>
                "Informe um endereço de e-mail válido.",
            _ => "Revise os dados informados e tente novamente."
        };

        return new ManagementValidationException(
            reasonCode,
            message,
            field);
    }

    private sealed class ProfileIdentityException(
        IdentityResult result) : Exception
    {
        public IdentityResult Result { get; } = result;
    }

    private async Task<ManagementAuthorizationDecision> DemandAsync(
        ManagementRequestContext context,
        string capability,
        ManagementResource resource,
        CancellationToken cancellationToken)
    {
        var decision = await authorization.EvaluateAsync(
            context.Operator,
            capability,
            resource,
            cancellationToken);
        if (decision.IsAllowed)
        {
            return decision;
        }

        await WriteAuditAsync(
            context,
            capability,
            resource,
            decision,
            "denied",
            decision.ReasonCode,
            cancellationToken);
        throw new ManagementAccessException(decision);
    }

    private async Task WriteAuditAsync(
        ManagementRequestContext context,
        string capability,
        ManagementResource resource,
        ManagementAuthorizationDecision decision,
        string operationOutcome,
        string reasonCode,
        CancellationToken cancellationToken)
    {
        try
        {
            database.ManagementAuditEvents.Add(ManagementAuditEventFactory.Create(
                context,
                capability,
                resource,
                decision,
                operationOutcome,
                reasonCode));
            await database.SaveChangesAsync(cancellationToken);
        }
        catch (Exception exception)
        {
            logger.LogError(
                exception,
                "Unable to persist user-management audit event. CorrelationId={CorrelationId}",
                context.CorrelationId);
        }
    }

    private Task TryWriteAuditAsync(
        ManagementRequestContext context,
        string capability,
        ManagementResource resource,
        ManagementAuthorizationDecision decision,
        string operationOutcome,
        string reasonCode,
        CancellationToken cancellationToken) =>
        WriteAuditAsync(
            context,
            capability,
            resource,
            decision,
            operationOutcome,
            reasonCode,
            cancellationToken);
}
