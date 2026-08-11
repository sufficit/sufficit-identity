#if !APPLICATION_CONTRACTS
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
#endif
using Sufficit.Identity.Management.Authorization;

namespace Sufficit.Identity.Management.Claims;

#if APPLICATION_CONTRACTS

/// <summary>
/// Canonical application boundary for custom claims assigned to identity
/// accounts. The embedded UI and HTTP API are adapters over this service.
/// </summary>
public interface IClaimManagementService
{
    Task<ManagementClaimMetadata> GetMetadataAsync(
        ManagementRequestContext context,
        CancellationToken cancellationToken = default);

    Task<ManagementClaimPage> SearchAsync(
        ManagementClaimSearch query,
        ManagementRequestContext context,
        CancellationToken cancellationToken = default);

    Task<ManagementClaimAssignment> GetAsync(
        int id,
        ManagementRequestContext context,
        CancellationToken cancellationToken = default);

    Task<ManagementClaimAssignment> CreateAsync(
        CreateManagementClaimCommand command,
        ManagementRequestContext context,
        CancellationToken cancellationToken = default);

    Task<ManagementClaimAssignment> UpdateAsync(
        int id,
        UpdateManagementClaimCommand command,
        ManagementRequestContext context,
        CancellationToken cancellationToken = default);

    Task DeleteAsync(
        int id,
        ManagementRequestContext context,
        CancellationToken cancellationToken = default);
}

public sealed record ManagementClaimMetadata(
    IReadOnlyList<string> SuggestedTypes,
    int TypeMaxLength,
    int ValueMaxLength);

public sealed record ManagementClaimSearch(
    string? Search = null,
    string? UserId = null,
    int Page = 1,
    int PageSize = 25);

public sealed record ManagementClaimPage(
    IReadOnlyList<ManagementClaimAssignment> Items,
    int Page,
    int PageSize,
    int TotalCount,
    string? UserId);

public sealed record ManagementClaimAssignment(
    int Id,
    string UserId,
    string? UserName,
    string? Email,
    string Type,
    string Value);

public sealed record CreateManagementClaimCommand(
    string UserId,
    string Type,
    string Value);

public sealed record UpdateManagementClaimCommand(
    string Type,
    string Value);

#else

internal sealed class ClaimManagementService(
    AppDbContext database,
    UserManager<ApplicationUser> userManager,
    IManagementAuthorizationEvaluator authorization,
    IIdentityUserSessionRevoker sessionRevoker,
    ISecurityEventTrigger securityEvents,
    IOptions<Sufficit.Identity.Management.ManagementOptions> managementOptions,
    ILogger<ClaimManagementService> logger) : IClaimManagementService
{
    private const int ClaimTypeMaxLength = 256;
    private const int ClaimValueMaxLength = 4096;

    private static readonly HashSet<string> ReservedClaimTypes =
        new(StringComparer.OrdinalIgnoreCase)
        {
            OidcClaims.Subject,
            OidcClaims.Name,
            OidcClaims.PreferredUsername,
            OidcClaims.Email,
            OidcClaims.EmailVerified,
            OidcClaims.PhoneNumber,
            OidcClaims.PhoneNumberVerified,
            OidcClaims.Role,
            "amr",
            "auth_time",
            "azp",
            "aud",
            "iss",
            "exp",
            "iat",
            "nbf",
            "jti",
            "nonce",
            "at_hash",
            "c_hash",
            "sid",
            "aal",
            // Prevent claims→super-admin escalation (finding #2): the capability
            // resolver reads capabilities from "permission" claims. If an
            // operator with only claims.create writes a "permission" claim to
            // themselves, they gain arbitrary management capabilities. Blocking
            // these claim types prevents the separation-of-duties break.
            "permission",
            "scope",
            ClaimTypes.NameIdentifier,
            ClaimTypes.Name,
            ClaimTypes.Email,
            ClaimTypes.Role,
            ClaimTypes.MobilePhone,
            "AspNet.Identity.SecurityStamp"
        };

    private static readonly string[] SuggestedClaimTypes =
    [
        "address",
        "birthdate",
        "family_name",
        "gender",
        "given_name",
        "locale",
        "middle_name",
        "nickname",
        "picture",
        "profile",
        "updated_at",
        "website",
        "zoneinfo"
    ];

    public async Task<ManagementClaimMetadata> GetMetadataAsync(
        ManagementRequestContext context,
        CancellationToken cancellationToken = default)
    {
        await DemandAsync(
            context,
            ManagementCapabilities.ClaimsRead,
            new ManagementResource(
                ManagementResourceTypes.ClaimCollection),
            cancellationToken);

        return new ManagementClaimMetadata(
            SuggestedClaimTypes,
            ClaimTypeMaxLength,
            ClaimValueMaxLength);
    }

    public async Task<ManagementClaimPage> SearchAsync(
        ManagementClaimSearch query,
        ManagementRequestContext context,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(query);

        var page = Math.Max(query.Page, 1);
        var pageSize = Math.Clamp(query.PageSize, 1, 100);
        var userId = NullIfWhiteSpace(query.UserId);
        var resource = new ManagementResource(
            ManagementResourceTypes.ClaimCollection,
            userId);
        var decision = await DemandAsync(
            context,
            ManagementCapabilities.ClaimsRead,
            resource,
            cancellationToken);

        var claims =
            from claim in database.Set<IdentityUserClaim<string>>()
                .AsNoTracking()
            join user in database.Users.AsNoTracking()
                on claim.UserId equals user.Id
            select new
            {
                claim.Id,
                claim.UserId,
                user.UserName,
                user.Email,
                claim.ClaimType,
                claim.ClaimValue
            };

        if (userId is not null)
        {
            claims = claims.Where(claim => claim.UserId == userId);
        }

        var search = NullIfWhiteSpace(query.Search);
        if (search is not null)
        {
            claims = claims.Where(claim =>
                claim.ClaimType != null && claim.ClaimType.Contains(search)
                || claim.ClaimValue != null && claim.ClaimValue.Contains(search)
                || claim.UserName != null && claim.UserName.Contains(search)
                || claim.Email != null && claim.Email.Contains(search));
        }

        var totalCount = await claims.CountAsync(cancellationToken);
        var items = await claims
            .OrderBy(claim => claim.ClaimType)
            .ThenBy(claim => claim.UserName ?? claim.Email ?? claim.UserId)
            .ThenBy(claim => claim.Id)
            .Skip((page - 1) * pageSize)
            .Take(pageSize)
            .Select(claim => new ManagementClaimAssignment(
                claim.Id,
                claim.UserId,
                claim.UserName,
                claim.Email,
                claim.ClaimType ?? string.Empty,
                claim.ClaimValue ?? string.Empty))
            .ToArrayAsync(cancellationToken);

        // L3 fix (eval): no audit row on read paths.

        return new ManagementClaimPage(
            items,
            page,
            pageSize,
            totalCount,
            userId);
    }

    public async Task<ManagementClaimAssignment> GetAsync(
        int id,
        ManagementRequestContext context,
        CancellationToken cancellationToken = default)
    {
        var resource = new ManagementResource(
            ManagementResourceTypes.Claim,
            id.ToString());
        var decision = await DemandAsync(
            context,
            ManagementCapabilities.ClaimsRead,
            resource,
            cancellationToken);
        var claim = await FindAsync(id, cancellationToken);
        if (claim is null)
        {
            throw new ManagementNotFoundException(
                "claim_not_found",
                "A claim atribuída não foi encontrada.");
        }

        // L3 fix (eval): no audit row on read paths.
        return claim;
    }

    public async Task<ManagementClaimAssignment> CreateAsync(
        CreateManagementClaimCommand command,
        ManagementRequestContext context,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(command);

        var userId = Required(
            command.UserId,
            "claim_user_required",
            "Selecione a conta que receberá a claim.",
            "userId");
        var type = ValidateClaimType(command.Type);
        var value = ValidateClaimValue(command.Value);
        var resource = new ManagementResource(
            ManagementResourceTypes.ClaimCollection,
            userId);
        var decision = await DemandAsync(
            context,
            ManagementCapabilities.ClaimsCreate,
            resource,
            cancellationToken);

        var user = await userManager.FindByIdAsync(userId);
        if (user is null)
        {
            throw new ManagementNotFoundException(
                "claim_user_not_found",
                "A conta selecionada não foi encontrada.");
        }

        var claimSet = database.Set<IdentityUserClaim<string>>();
        if (await claimSet.AnyAsync(
                claim =>
                    claim.UserId == userId
                    && claim.ClaimType == type
                    && claim.ClaimValue == value,
                cancellationToken))
        {
            throw new ManagementConflictException(
                "claim_already_assigned",
                "Essa conta já possui a mesma claim e valor.");
        }

        await using var transaction = await database.Database
            .BeginTransactionAsync(cancellationToken);
        try
        {
            var claim = new IdentityUserClaim<string>
            {
                UserId = userId,
                ClaimType = type,
                ClaimValue = value
            };
            claimSet.Add(claim);
            await database.SaveChangesAsync(cancellationToken);

            EnsureIdentitySucceeded(
                await userManager.UpdateSecurityStampAsync(user),
                "claim_session_invalidation_failed");
            var revokedTokens = await sessionRevoker.RevokeTokensAsync(
                userId,
                cancellationToken);

            database.ManagementAuditEvents.Add(
                ManagementAuditEventFactory.Create(
                    context,
                    ManagementCapabilities.ClaimsCreate,
                    new ManagementResource(
                        ManagementResourceTypes.Claim,
                        claim.Id.ToString()),
                    decision,
                    "succeeded",
                    "claim_assigned"));
            await database.SaveChangesAsync(cancellationToken);
            await transaction.CommitAsync(cancellationToken);

            logger.LogInformation(
                "Assigned custom claim {ClaimType} to identity account {UserId} and revoked {TokenCount} tokens. CorrelationId={CorrelationId}",
                type,
                userId,
                revokedTokens,
                context.CorrelationId);

            await securityEvents.CredentialChangedAsync(
                userId,
                null,
                new CaepCredentialChange(
                    CaepCredentialType.Privilege,
                    CaepChangeOperation.Created),
                cancellationToken);

            return new ManagementClaimAssignment(
                claim.Id,
                userId,
                user.UserName,
                user.Email,
                type,
                value);
        }
        catch (ManagementConflictException)
        {
            throw;
        }
        catch (OperationCanceledException)
        {
            throw;
        }
        catch (Exception exception)
        {
            await transaction.RollbackAsync(CancellationToken.None);
            database.ChangeTracker.Clear();
            logger.LogError(
                exception,
                "Unable to assign a custom claim. UserId={UserId} ClaimType={ClaimType} CorrelationId={CorrelationId}",
                userId,
                type,
                context.CorrelationId);
            await TryWriteFailureAuditAsync(
                context,
                ManagementCapabilities.ClaimsCreate,
                resource,
                decision,
                "claim_assign_failed");
            throw new ManagementConflictException(
                "claim_assign_failed",
                "Não foi possível atribuir a claim.");
        }
    }

    public async Task DeleteAsync(
        int id,
        ManagementRequestContext context,
        CancellationToken cancellationToken = default)
    {
        var resource = new ManagementResource(
            ManagementResourceTypes.Claim,
            id.ToString());
        var decision = await DemandAsync(
            context,
            ManagementCapabilities.ClaimsDelete,
            resource,
            cancellationToken);
        var claim = await database.Set<IdentityUserClaim<string>>()
            .SingleOrDefaultAsync(item => item.Id == id, cancellationToken);
        if (claim is null)
        {
            throw new ManagementNotFoundException(
                "claim_not_found",
                "A claim atribuída não foi encontrada.");
        }

        var user = await userManager.FindByIdAsync(claim.UserId);
        if (user is null)
        {
            throw new ManagementConflictException(
                "claim_user_not_found",
                "A conta vinculada à claim não foi encontrada.");
        }

        await using var transaction = await database.Database
            .BeginTransactionAsync(cancellationToken);
        try
        {
            database.Remove(claim);
            EnsureIdentitySucceeded(
                await userManager.UpdateSecurityStampAsync(user),
                "claim_session_invalidation_failed");
            var revokedTokens = await sessionRevoker.RevokeTokensAsync(
                user.Id,
                cancellationToken);
            database.ManagementAuditEvents.Add(
                ManagementAuditEventFactory.Create(
                    context,
                    ManagementCapabilities.ClaimsDelete,
                    resource,
                    decision,
                    "succeeded",
                    "claim_removed"));
            await database.SaveChangesAsync(cancellationToken);
            await transaction.CommitAsync(cancellationToken);

            logger.LogInformation(
                "Removed custom claim {ClaimType} from identity account {UserId} and revoked {TokenCount} tokens. CorrelationId={CorrelationId}",
                claim.ClaimType,
                user.Id,
                revokedTokens,
                context.CorrelationId);

            await securityEvents.CredentialChangedAsync(
                user.Id,
                null,
                new CaepCredentialChange(
                    CaepCredentialType.Privilege,
                    CaepChangeOperation.Deleted),
                cancellationToken);
        }
        catch (OperationCanceledException)
        {
            throw;
        }
        catch (Exception exception)
        {
            await transaction.RollbackAsync(CancellationToken.None);
            database.ChangeTracker.Clear();
            logger.LogError(
                exception,
                "Unable to remove custom claim {ClaimId}. CorrelationId={CorrelationId}",
                id,
                context.CorrelationId);
            await TryWriteFailureAuditAsync(
                context,
                ManagementCapabilities.ClaimsDelete,
                resource,
                decision,
                "claim_remove_failed");
            throw new ManagementConflictException(
                "claim_remove_failed",
                "Não foi possível remover a claim.");
        }
    }

    public async Task<ManagementClaimAssignment> UpdateAsync(
        int id,
        UpdateManagementClaimCommand command,
        ManagementRequestContext context,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(command);

        var type = ValidateClaimType(command.Type);
        var value = ValidateClaimValue(command.Value);
        var resource = new ManagementResource(
            ManagementResourceTypes.Claim,
            id.ToString());
        var decision = await DemandAsync(
            context,
            ManagementCapabilities.ClaimsUpdate,
            resource,
            cancellationToken);
        var claim = await database.Set<IdentityUserClaim<string>>()
            .SingleOrDefaultAsync(item => item.Id == id, cancellationToken);
        if (claim is null)
        {
            throw new ManagementNotFoundException(
                "claim_not_found",
                "A claim atribuída não foi encontrada.");
        }

        var user = await userManager.FindByIdAsync(claim.UserId);
        if (user is null)
        {
            throw new ManagementConflictException(
                "claim_user_not_found",
                "A conta vinculada à claim não foi encontrada.");
        }

        if (await database.Set<IdentityUserClaim<string>>().AnyAsync(
                item =>
                    item.Id != id
                    && item.UserId == claim.UserId
                    && item.ClaimType == type
                    && item.ClaimValue == value,
                cancellationToken))
        {
            throw new ManagementConflictException(
                "claim_already_assigned",
                "Essa conta já possui a mesma claim e valor.");
        }

        await using var transaction = await database.Database
            .BeginTransactionAsync(cancellationToken);
        try
        {
            claim.ClaimType = type;
            claim.ClaimValue = value;
            await database.SaveChangesAsync(cancellationToken);

            EnsureIdentitySucceeded(
                await userManager.UpdateSecurityStampAsync(user),
                "claim_session_invalidation_failed");
            var revokedTokens = await sessionRevoker.RevokeTokensAsync(
                user.Id,
                cancellationToken);

            database.ManagementAuditEvents.Add(
                ManagementAuditEventFactory.Create(
                    context,
                    ManagementCapabilities.ClaimsUpdate,
                    resource,
                    decision,
                    "succeeded",
                    "claim_updated"));
            await database.SaveChangesAsync(cancellationToken);
            await transaction.CommitAsync(cancellationToken);

            logger.LogInformation(
                "Updated custom claim {ClaimId} for identity account {UserId} and revoked {TokenCount} tokens. CorrelationId={CorrelationId}",
                id,
                user.Id,
                revokedTokens,
                context.CorrelationId);

            await securityEvents.CredentialChangedAsync(
                user.Id,
                null,
                new CaepCredentialChange(
                    CaepCredentialType.Privilege,
                    CaepChangeOperation.Updated),
                cancellationToken);

            return new ManagementClaimAssignment(
                id,
                user.Id,
                user.UserName,
                user.Email,
                type,
                value);
        }
        catch (ManagementConflictException)
        {
            throw;
        }
        catch (OperationCanceledException)
        {
            throw;
        }
        catch (Exception exception)
        {
            await transaction.RollbackAsync(CancellationToken.None);
            database.ChangeTracker.Clear();
            logger.LogError(
                exception,
                "Unable to update custom claim {ClaimId}. CorrelationId={CorrelationId}",
                id,
                context.CorrelationId);
            await TryWriteFailureAuditAsync(
                context,
                ManagementCapabilities.ClaimsUpdate,
                resource,
                decision,
                "claim_update_failed");
            throw new ManagementConflictException(
                "claim_update_failed",
                "Não foi possível atualizar a claim.");
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
        if (!decision.IsAllowed)
        {
            throw new ManagementAccessException(decision);
        }

        return decision;
    }

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
                ManagementTenantClaims.Type,
                StringComparison.OrdinalIgnoreCase)
            || string.Equals(
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
}
#endif
