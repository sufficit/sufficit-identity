using Sufficit.Identity.Management.Audit;
using Sufficit.Identity.Management.Authorization;

namespace Sufficit.Identity.Management.Vault;

public interface IVaultSecretsManagementService
{
    Task<IReadOnlyList<ManagementVaultSecret>> ListAsync(
        string contextId,
        ManagementRequestContext context,
        CancellationToken cancellationToken = default);

    Task<ManagementVaultSecret?> GetAsync(
        string name,
        string contextId,
        ManagementRequestContext context,
        CancellationToken cancellationToken = default);

    /// <summary>Plaintext disclosure. Requires the dedicated resolve
    /// capability and journals every call. Returns null when the secret does
    /// not exist; an expired secret is returned with a null value and
    /// <see cref="VaultSecretStatus.Expired"/> so the API can answer 410.</summary>
    Task<ResolvedManagementVaultSecret?> ResolveAsync(
        string name,
        string contextId,
        ManagementRequestContext context,
        CancellationToken cancellationToken = default);

    Task<ManagementVaultSecret> PutAsync(
        string name,
        string contextId,
        SaveManagementVaultSecret command,
        ManagementRequestContext context,
        CancellationToken cancellationToken = default);

    Task DeleteAsync(
        string name,
        string contextId,
        ManagementRequestContext context,
        CancellationToken cancellationToken = default);
}

public enum VaultSecretStatus
{
    Active,
    ExpiringSoon,
    Expired,
}

/// <summary>Shared expiration semantics so every surface (management API,
/// clients, UI) reports the same status for the same instant.</summary>
public static class VaultSecretExpiration
{
    /// <summary>Secrets expiring within this window report
    /// <see cref="VaultSecretStatus.ExpiringSoon"/> so operators can rotate
    /// before resolution starts failing.</summary>
    public static readonly TimeSpan ExpiringSoonWindow = TimeSpan.FromDays(7);

    public static VaultSecretStatus GetStatus(
        DateTime? expiresAtUtc,
        DateTime nowUtc)
    {
        if (expiresAtUtc is not { } expiration) return VaultSecretStatus.Active;
        if (expiration <= nowUtc) return VaultSecretStatus.Expired;
        return expiration - nowUtc <= ExpiringSoonWindow
            ? VaultSecretStatus.ExpiringSoon
            : VaultSecretStatus.Active;
    }
}

public sealed record ManagementVaultSecret(
    string Name,
    string Namespace,
    string ContextId,
    string OwnerSubject,
    DateTime UpdatedAtUtc,
    string UpdatedBy,
    bool HasValue,
    DateTime? ExpiresAtUtc = null,
    VaultSecretStatus Status = VaultSecretStatus.Active);

public sealed record ResolvedManagementVaultSecret(
    string Name,
    string Namespace,
    string ContextId,
    string? Value,
    VaultSecretStatus Status,
    DateTime? ExpiresAtUtc,
    DateTime UpdatedAtUtc);

public sealed record SaveManagementVaultSecret(
    string Value,
    DateTime? ExpiresAtUtc = null);
