using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Options;
using Sufficit.Identity.Core.Data;
using Sufficit.Identity.Management.Audit;
using Sufficit.Identity.Management.Authorization;
using Sufficit.Identity.Vault;

namespace Sufficit.Identity.Management.Vault;

/// <summary>
/// Administrative inventory for user-bound Vault data. Queries project only
/// metadata and counts; no operation in this service decrypts a value.
/// </summary>
public sealed class UserVaultManagementService(
    AppDbContext database,
    IVaultNamedSecretStore namedSecrets,
    IOptions<VaultOptions> options,
    ManagementOperationGuard guard) : IUserVaultManagementService
{
    private const string UserContextPrefix = "user-";
    private const string OAuthPendingPrefix = "integrations/oauth/pending/";

    public async Task<VaultUserInventoryPage> ListUsersAsync(
        VaultUserInventoryQuery query,
        ManagementRequestContext context,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(query);
        await guard.DemandAsync(
            context,
            ManagementCapabilities.VaultSecretsRead,
            new ManagementResource(ManagementResourceTypes.VaultUserCollection),
            cancellationToken);
        EnsureEnabled();

        var personal = await database.VaultPersonalSecrets
            .AsNoTracking()
            .GroupBy(item => item.OwnerSubject)
            .Select(group => new VaultOwnerAggregate(
                group.Key,
                group.Count(),
                group.Max(item => item.UpdatedAtUtc)))
            .ToArrayAsync(cancellationToken);
        var managed = await database.VaultSecrets
            .AsNoTracking()
            .Where(item => item.ContextId.StartsWith(UserContextPrefix)
                && !item.Name.StartsWith(OAuthPendingPrefix))
            .GroupBy(item => item.ContextId)
            .Select(group => new VaultOwnerAggregate(
                group.Key,
                group.Count(),
                group.Max(item => item.UpdatedAtUtc)))
            .ToArrayAsync(cancellationToken);

        var owners = new Dictionary<string, MutableInventory>(
            StringComparer.OrdinalIgnoreCase);
        foreach (var item in personal)
        {
            owners[item.OwnerSubject] = new MutableInventory
            {
                OwnerSubject = item.OwnerSubject,
                PersonalSecretCount = item.Count,
                LastUpdatedAtUtc = item.LastUpdatedAtUtc,
            };
        }

        foreach (var item in managed)
        {
            if (item.OwnerSubject.Length <= UserContextPrefix.Length) continue;
            var ownerSubject = item.OwnerSubject[UserContextPrefix.Length..];
            if (!owners.TryGetValue(ownerSubject, out var inventory))
            {
                inventory = new MutableInventory { OwnerSubject = ownerSubject };
                owners.Add(ownerSubject, inventory);
            }

            inventory.ManagedCredentialCount = item.Count;
            inventory.LastUpdatedAtUtc = Latest(
                inventory.LastUpdatedAtUtc,
                item.LastUpdatedAtUtc);
        }

        var ownerSubjects = owners.Keys.ToArray();
        var users = ownerSubjects.Length == 0
            ? []
            : await database.Users.AsNoTracking()
                .Where(user => ownerSubjects.Contains(user.Id))
                .Select(user => new VaultUserIdentity(
                    user.Id,
                    user.UserName,
                    user.Email))
                .ToArrayAsync(cancellationToken);
        foreach (var user in users)
        {
            if (!owners.TryGetValue(user.OwnerSubject, out var inventory))
                continue;
            inventory.UserName = user.UserName;
            inventory.Email = user.Email;
            inventory.UserExists = true;
        }

        var search = query.Search?.Trim();
        var filtered = owners.Values
            .Where(item => Matches(item, search))
            .OrderByDescending(item => item.LastUpdatedAtUtc)
            .ThenBy(item => item.Email ?? item.UserName ?? item.OwnerSubject,
                StringComparer.OrdinalIgnoreCase)
            .ToArray();
        var offset = Math.Clamp(query.Offset, 0, filtered.Length);
        var limit = Math.Clamp(query.Limit, 1, 100);
        var items = filtered
            .Skip(offset)
            .Take(limit)
            .Select(ToContract)
            .ToArray();

        return new VaultUserInventoryPage(
            items,
            filtered.Length,
            filtered.Sum(item => item.PersonalSecretCount),
            filtered.Sum(item => item.ManagedCredentialCount),
            offset,
            limit);
    }

    public async Task<VaultUserDetail?> GetUserAsync(
        string ownerSubject,
        ManagementRequestContext context,
        CancellationToken cancellationToken = default)
    {
        var owner = NormalizeOwner(ownerSubject);
        await guard.DemandAsync(
            context,
            ManagementCapabilities.VaultSecretsRead,
            UserResource(owner),
            cancellationToken);
        EnsureEnabled();

        var personal = await database.VaultPersonalSecrets
            .AsNoTracking()
            .Where(item => item.OwnerSubject == owner)
            .OrderBy(item => item.Namespace)
            .ThenBy(item => item.Name)
            .Select(item => new UserVaultSecretMetadata(
                item.Namespace,
                item.Name,
                item.UpdatedAtUtc,
                item.UpdatedBy,
                true))
            .ToArrayAsync(cancellationToken);
        var managedMetadata = await namedSecrets.ListAsync(
            ContextFor(owner),
            namespaces: null,
            cancellationToken);
        var managed = managedMetadata
            .Where(item => !item.Name.StartsWith(
                OAuthPendingPrefix,
                StringComparison.Ordinal))
            .Select(item => new UserVaultManagedCredentialMetadata(
                item.Name,
                item.Namespace,
                ProviderFrom(item.Name),
                item.UpdatedAtUtc,
                item.ExpiresAtUtc))
            .OrderBy(item => item.Provider ?? item.Name, StringComparer.Ordinal)
            .ToArray();
        var user = await database.Users.AsNoTracking()
            .Where(item => item.Id == owner)
            .Select(item => new VaultUserIdentity(
                item.Id,
                item.UserName,
                item.Email))
            .SingleOrDefaultAsync(cancellationToken);

        if (user is null && personal.Length == 0 && managed.Length == 0)
            return null;

        var lastUpdated = personal.Select(item => item.UpdatedAtUtc)
            .Concat(managed.Select(item => item.UpdatedAtUtc))
            .DefaultIfEmpty()
            .Max();
        return new VaultUserDetail(
            new VaultUserInventoryItem(
                owner,
                user?.UserName,
                user?.Email,
                user is not null,
                personal.Length,
                managed.Length,
                lastUpdated == default ? null : lastUpdated),
            personal,
            managed);
    }

    public async Task DeletePersonalSecretAsync(
        string ownerSubject,
        string @namespace,
        string name,
        ManagementRequestContext context,
        CancellationToken cancellationToken = default)
    {
        var owner = NormalizeOwner(ownerSubject);
        var scope = VaultBackedSecretStore.NormalizeNamespace(@namespace);
        var normalizedName = VaultBackedSecretStore.NormalizeName(name);
        var decision = await guard.DemandAsync(
            context,
            ManagementCapabilities.VaultSecretsManage,
            UserResource(owner),
            cancellationToken,
            auditDenial: true);
        EnsureEnabled();

        var deleted = await database.VaultPersonalSecrets
            .Where(item => item.OwnerSubject == owner
                && item.Namespace == scope
                && item.Name == normalizedName)
            .ExecuteDeleteAsync(cancellationToken);
        if (deleted == 0)
            throw new ManagementNotFoundException(
                "personal_secret_not_found",
                "Credencial pessoal não encontrada.");
        await AuditAsync(
            context,
            UserResource(owner),
            decision,
            "vault_user_personal_secret_deleted",
            cancellationToken);
    }

    public async Task DeleteManagedCredentialAsync(
        string ownerSubject,
        string name,
        ManagementRequestContext context,
        CancellationToken cancellationToken = default)
    {
        var owner = NormalizeOwner(ownerSubject);
        var normalizedName = VaultBackedSecretStore.NormalizeName(name);
        if (normalizedName.StartsWith(OAuthPendingPrefix, StringComparison.Ordinal))
            throw new ManagementNotFoundException(
                "managed_credential_not_found",
                "Credencial conectada não encontrada.");
        var decision = await guard.DemandAsync(
            context,
            ManagementCapabilities.VaultSecretsManage,
            UserResource(owner),
            cancellationToken,
            auditDenial: true);
        EnsureEnabled();

        if (!await namedSecrets.DeleteAsync(
                normalizedName,
                ContextFor(owner),
                cancellationToken))
            throw new ManagementNotFoundException(
                "managed_credential_not_found",
                "Credencial conectada não encontrada.");
        await AuditAsync(
            context,
            UserResource(owner),
            decision,
            "vault_user_managed_credential_deleted",
            cancellationToken);
    }

    public async Task<VaultUserCleanupResult> ClearUserAsync(
        string ownerSubject,
        ManagementRequestContext context,
        CancellationToken cancellationToken = default)
    {
        var owner = NormalizeOwner(ownerSubject);
        var resource = UserResource(owner);
        var decision = await guard.DemandAsync(
            context,
            ManagementCapabilities.VaultSecretsManage,
            resource,
            cancellationToken,
            auditDenial: true);
        EnsureEnabled();

        var personalDeleted = await database.VaultPersonalSecrets
            .Where(item => item.OwnerSubject == owner)
            .ExecuteDeleteAsync(cancellationToken);
        var managed = await namedSecrets.ListAsync(
            ContextFor(owner),
            namespaces: null,
            cancellationToken);
        var managedDeleted = 0;
        foreach (var item in managed.Where(item => !item.Name.StartsWith(
                     OAuthPendingPrefix,
                     StringComparison.Ordinal)))
        {
            if (await namedSecrets.DeleteAsync(
                    item.Name,
                    item.ContextId,
                    cancellationToken))
                managedDeleted++;
        }

        if (personalDeleted == 0 && managedDeleted == 0)
            throw new ManagementNotFoundException(
                "vault_user_empty",
                "Este usuário não possui credenciais armazenadas.");
        await AuditAsync(
            context,
            resource,
            decision,
            "vault_user_cleared",
            cancellationToken);
        return new VaultUserCleanupResult(personalDeleted, managedDeleted);
    }

    private async Task AuditAsync(
        ManagementRequestContext context,
        ManagementResource resource,
        ManagementAuthorizationDecision decision,
        string reason,
        CancellationToken cancellationToken)
    {
        database.ManagementAuditEvents.Add(
            ManagementAuditEventFactory.Create(
                context,
                ManagementCapabilities.VaultSecretsManage,
                resource,
                decision,
                "succeeded",
                reason));
        await database.SaveChangesAsync(cancellationToken);
    }

    private void EnsureEnabled()
    {
        if (!options.Value.Enabled)
            throw new ManagementValidationException(
                "vault_required",
                "Habilite Sufficit:Vault:Enabled antes de administrar credenciais.");
    }

    private static bool Matches(MutableInventory item, string? search) =>
        string.IsNullOrWhiteSpace(search)
        || Contains(item.OwnerSubject, search)
        || Contains(item.UserName, search)
        || Contains(item.Email, search);

    private static bool Contains(string? value, string search) =>
        value?.Contains(search, StringComparison.OrdinalIgnoreCase) == true;

    private static VaultUserInventoryItem ToContract(MutableInventory item) =>
        new(
            item.OwnerSubject,
            item.UserName,
            item.Email,
            item.UserExists,
            item.PersonalSecretCount,
            item.ManagedCredentialCount,
            item.LastUpdatedAtUtc);

    private static DateTime? Latest(DateTime? left, DateTime right) =>
        left is null || right > left ? right : left;

    private static string NormalizeOwner(string ownerSubject)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(ownerSubject);
        var owner = ownerSubject.Trim();
        return owner.Length <= 255
            ? owner
            : throw new ArgumentException(
                "Owner subject is too long.",
                nameof(ownerSubject));
    }

    private static string ContextFor(string ownerSubject) =>
        VaultBackedSecretStore.NormalizeContextId(
            UserContextPrefix + ownerSubject.ToLowerInvariant());

    private static ManagementResource UserResource(string ownerSubject) =>
        new(ManagementResourceTypes.VaultUser, ownerSubject);

    private static string? ProviderFrom(string name)
    {
        const string prefix = "integrations/oauth/tokens/";
        if (!name.StartsWith(prefix, StringComparison.Ordinal)) return null;
        var provider = name[prefix.Length..];
        return provider.Length > 0 && !provider.Contains('/') ? provider : null;
    }

    private sealed record VaultOwnerAggregate(
        string OwnerSubject,
        int Count,
        DateTime LastUpdatedAtUtc);

    private sealed record VaultUserIdentity(
        string OwnerSubject,
        string? UserName,
        string? Email);

    private sealed class MutableInventory
    {
        public required string OwnerSubject { get; init; }
        public string? UserName { get; set; }
        public string? Email { get; set; }
        public bool UserExists { get; set; }
        public int PersonalSecretCount { get; set; }
        public int ManagedCredentialCount { get; set; }
        public DateTime? LastUpdatedAtUtc { get; set; }
    }
}
