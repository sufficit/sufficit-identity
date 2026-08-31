using System.Security.Claims;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using OpenIddict.Abstractions;
using Sufficit.Identity.Core.Data;
using Sufficit.Identity.Core.Entities;
using Sufficit.Identity.Core.Services;
using Sufficit.Identity.Application.Accounts;
using Sufficit.Identity.Application.Security;
using Sufficit.Identity.Management.Audit;
using Sufficit.Identity.Management.Users;
using OidcClaims = OpenIddict.Abstractions.OpenIddictConstants.Claims;
using Sufficit.Identity.Management.Authorization;

namespace Sufficit.Identity.Management.Claims;

internal sealed partial class ClaimManagementService
{
    private string ValidateClaimType(string? value)
    {
        var type = Required(
            value,
            "claim_type_required",
            "Informe o tipo da claim.",
            "type");
        if (type.Length > ClaimTypeMaxLength)
        {
            throw new ManagementValidationException(
                "claim_type_too_long",
                $"Use no máximo {ClaimTypeMaxLength} caracteres.",
                "type");
        }
        if (type.Any(char.IsWhiteSpace) || type.Any(char.IsControl))
        {
            throw new ManagementValidationException(
                "claim_type_invalid",
                "O tipo da claim não pode conter espaços ou caracteres de controle.",
                "type");
        }
        if (IsAuthorizationSensitiveClaimType(type))
        {
            throw new ManagementValidationException(
                "claim_type_reserved",
                "Essa claim é derivada pelo protocolo ou pelo perfil e não pode ser atribuída manualmente.",
                "type");
        }

        return type;
    }

    private bool IsAuthorizationSensitiveClaimType(string type)
    {
        if (ReservedClaimTypes.Contains(type)) return true;

        var authorization = managementOptions.Value.Authorization;
        return string.Equals(
                type,
                authorization.ProtectedPrincipals.TierClaimType,
                StringComparison.OrdinalIgnoreCase)
            || string.Equals(
                type,
                authorization.ProtectedPrincipals.BreakGlassClaimType,
                StringComparison.OrdinalIgnoreCase)
            || string.Equals(
                type,
                authorization.VaultSecrets.NamespaceClaimType,
                StringComparison.OrdinalIgnoreCase)
            || string.Equals(
                type,
                authorization.VaultSecrets.BreakGlassClaimType,
                StringComparison.OrdinalIgnoreCase)
            || authorization.CapabilityClaimTypes.Contains(
                type,
                StringComparer.OrdinalIgnoreCase);
    }

    private static string ValidateClaimValue(string? value)
    {
        if (string.IsNullOrWhiteSpace(value))
        {
            throw new ManagementValidationException(
                "claim_value_required",
                "Informe o valor da claim.",
                "value");
        }
        if (value.Length > ClaimValueMaxLength)
        {
            throw new ManagementValidationException(
                "claim_value_too_long",
                $"Use no máximo {ClaimValueMaxLength} caracteres.",
                "value");
        }
        if (value.Contains('\0', StringComparison.Ordinal))
        {
            throw new ManagementValidationException(
                "claim_value_invalid",
                "O valor da claim contém um caractere inválido.",
                "value");
        }

        return value;
    }

    private static string Required(
        string? value,
        string reasonCode,
        string message,
        string field)
    {
        var normalized = value?.Trim();
        if (string.IsNullOrWhiteSpace(normalized))
        {
            throw new ManagementValidationException(
                reasonCode,
                message,
                field);
        }

        return normalized;
    }

    private static string? NullIfWhiteSpace(string? value) =>
        string.IsNullOrWhiteSpace(value) ? null : value.Trim();

    private static void EnsureIdentitySucceeded(
        IdentityResult result,
        string reasonCode)
    {
        if (!result.Succeeded)
        {
            throw new ManagementConflictException(
                reasonCode,
                "Não foi possível invalidar as sessões da conta.");
        }
    }

    private async Task<ManagementClaimAssignment?> FindAsync(
        int id,
        CancellationToken cancellationToken) =>
        await (
            from claim in database.Set<IdentityUserClaim<string>>()
                .AsNoTracking()
            join user in database.Users.AsNoTracking()
                on claim.UserId equals user.Id
            where claim.Id == id
            select new ManagementClaimAssignment(
                claim.Id,
                claim.UserId,
                user.UserName,
                user.Email,
                claim.ClaimType ?? string.Empty,
                claim.ClaimValue ?? string.Empty))
            .SingleOrDefaultAsync(cancellationToken);

    private async Task TryWriteFailureAuditAsync(
        ManagementRequestContext context,
        string capability,
        ManagementResource resource,
        ManagementAuthorizationDecision decision,
        string reasonCode)
    {
        try
        {
            database.ManagementAuditEvents.Add(
                ManagementAuditEventFactory.Create(
                    context,
                    capability,
                    resource,
                    decision,
                    "failed",
                    reasonCode));
            await database.SaveChangesAsync(CancellationToken.None);
        }
        catch (Exception exception)
        {
            logger.LogError(
                exception,
                "Unable to persist claim failure audit. CorrelationId={CorrelationId}",
                context.CorrelationId);
        }
    }
}
