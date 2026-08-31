namespace Sufficit.Identity.Management.Vault;

/// <summary>Application boundary for user-owned Vault entries.</summary>
public interface IUserVaultService
{
    Task<IReadOnlyList<UserVaultSecretMetadata>> ListAsync(
        string ownerSubject,
        string @namespace,
        CancellationToken cancellationToken = default);

    Task<UserVaultSecretMetadata?> GetAsync(
        string ownerSubject,
        string @namespace,
        string name,
        CancellationToken cancellationToken = default);

    Task<UserVaultSecretMetadata> PutAsync(
        string ownerSubject,
        string @namespace,
        string name,
        SaveUserVaultSecret command,
        CancellationToken cancellationToken = default);

    Task DeleteAsync(
        string ownerSubject,
        string @namespace,
        string name,
        CancellationToken cancellationToken = default);
}

/// <summary>
/// Read-only application boundary that composes user-managed secrets with
/// credentials maintained by connected applications. Implementations return
/// metadata only; secret values never cross this boundary.
/// </summary>
public interface IUserVaultOverviewService
{
    Task<UserVaultOverview> GetAsync(
        string ownerSubject,
        CancellationToken cancellationToken = default);
}

/// <summary>
/// Administrative metadata boundary for user Vaults. This contract never
/// exposes ciphertext, AAD or plaintext values; write operations can only
/// remove data and remain protected by the Vault management capability.
/// </summary>
public interface IUserVaultManagementService
{
    Task<VaultUserInventoryPage> ListUsersAsync(
        VaultUserInventoryQuery query,
        Authorization.ManagementRequestContext context,
        CancellationToken cancellationToken = default);

    Task<VaultUserDetail?> GetUserAsync(
        string ownerSubject,
        Authorization.ManagementRequestContext context,
        CancellationToken cancellationToken = default);

    Task DeletePersonalSecretAsync(
        string ownerSubject,
        string @namespace,
        string name,
        Authorization.ManagementRequestContext context,
        CancellationToken cancellationToken = default);

    Task DeleteManagedCredentialAsync(
        string ownerSubject,
        string name,
        Authorization.ManagementRequestContext context,
        CancellationToken cancellationToken = default);

    Task<VaultUserCleanupResult> ClearUserAsync(
        string ownerSubject,
        Authorization.ManagementRequestContext context,
        CancellationToken cancellationToken = default);
}

public sealed record VaultUserInventoryQuery(
    string? Search = null,
    int Offset = 0,
    int Limit = 25);

public sealed record VaultUserInventoryPage(
    IReadOnlyList<VaultUserInventoryItem> Items,
    int TotalUsers,
    int TotalPersonalSecrets,
    int TotalManagedCredentials,
    int Offset,
    int Limit);

public sealed record VaultUserInventoryItem(
    string OwnerSubject,
    string? UserName,
    string? Email,
    bool UserExists,
    int PersonalSecretCount,
    int ManagedCredentialCount,
    DateTime? LastUpdatedAtUtc);

public sealed record VaultUserDetail(
    VaultUserInventoryItem User,
    IReadOnlyList<UserVaultSecretMetadata> PersonalSecrets,
    IReadOnlyList<UserVaultManagedCredentialMetadata> ManagedCredentials);

public sealed record VaultUserCleanupResult(
    int PersonalSecretsDeleted,
    int ManagedCredentialsDeleted);

public sealed record UserVaultOverview(
    IReadOnlyList<UserVaultSecretMetadata> PersonalSecrets,
    IReadOnlyList<UserVaultManagedCredentialMetadata> ManagedCredentials);

public sealed record UserVaultManagedCredentialMetadata(
    string Name,
    string Namespace,
    string? Provider,
    DateTime UpdatedAtUtc,
    DateTime? ExpiresAtUtc);

public sealed record UserVaultSecretMetadata(
    string Namespace,
    string Name,
    DateTime UpdatedAtUtc,
    string UpdatedBy,
    bool HasValue);

public sealed record SaveUserVaultSecret(string Value);
