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
