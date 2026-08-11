using System.Text.Json;
using System.Security.Cryptography;
using Microsoft.EntityFrameworkCore;
using Sufficit.Identity.Core.Data;
using Sufficit.Identity.Core.Entities;

namespace Sufficit.Identity.Vault;

/// <summary>Metadata returned by the named-secret administration surface.</summary>
public sealed record VaultSecretMetadata(
    string Name,
    string Namespace,
    string ContextId,
    string OwnerSubject,
    DateTime UpdatedAtUtc,
    string UpdatedBy,
    bool HasValue);

/// <summary>
/// Database-backed named-secret store. Only ciphertext is persisted; the
/// plaintext boundary is limited to the caller that explicitly asks for a
/// secret (normally a server-side consumer, never the management response).
/// </summary>
public interface IVaultNamedSecretStore
{
    Task<string?> GetSecretAsync(
        string name,
        CancellationToken cancellationToken = default);

    Task<IReadOnlyList<VaultSecretMetadata>> ListAsync(
        CancellationToken cancellationToken = default);

    Task<IReadOnlyList<VaultSecretMetadata>> ListAsync(
        string contextId,
        IReadOnlySet<string>? namespaces,
        CancellationToken cancellationToken = default);

    Task<string?> GetSecretAsync(
        string name,
        string contextId,
        CancellationToken cancellationToken = default);

    Task<VaultSecretMetadata> PutAsync(
        string name,
        string value,
        string updatedBy,
        CancellationToken cancellationToken = default);

    Task<VaultSecretMetadata> PutAsync(
        string name,
        string value,
        string updatedBy,
        string contextId,
        CancellationToken cancellationToken = default);

    Task<bool> DeleteAsync(
        string name,
        CancellationToken cancellationToken = default);

    Task<bool> DeleteAsync(
        string name,
        string contextId,
        CancellationToken cancellationToken = default);
}

public sealed class VaultBackedSecretStore(
    IDbContextFactory<AppDbContext> databaseFactory,
    IKeyVault keyVault,
    VaultOptions options,
    VaultSnapshotCache? snapshots = null) : IVaultNamedSecretStore, ISecretStore
{
    private const string KeyName = "named-secrets";
    public const string GlobalContextId = "global";

    public async Task<string?> GetSecretAsync(
        string name,
        CancellationToken cancellationToken = default) =>
        await GetSecretAsync(name, GlobalContextId, cancellationToken);

    public async Task<string?> GetSecretAsync(
        string name,
        string contextId,
        CancellationToken cancellationToken = default)
    {
        EnsureEnabled();
        var normalized = NormalizeName(name);
        var normalizedContext = NormalizeContextId(contextId);
        if (snapshots is not null)
        {
            var snapshot = await snapshots.GetSecretAsync(
                normalized,
                normalizedContext,
                cancellationToken);
            if (snapshot is null) return null;

            return await keyVault.DecryptStringAsync(
                snapshot.Ciphertext,
                ReadAad(snapshot),
                cancellationToken);
        }

        await using var database = await databaseFactory.CreateDbContextAsync(
            cancellationToken);
        var item = await database.VaultSecrets.AsNoTracking()
            .SingleOrDefaultAsync(secret => secret.Name == normalized
                && secret.ContextId == normalizedContext,
                cancellationToken);
        if (item is null) return null;

        return await keyVault.DecryptStringAsync(
            item.Ciphertext,
            ReadAad(item),
            cancellationToken);
    }

    public async Task<IReadOnlyList<VaultSecretMetadata>> ListAsync(
        CancellationToken cancellationToken = default) =>
        await ListAsync(GlobalContextId, namespaces: null, cancellationToken);

    public async Task<IReadOnlyList<VaultSecretMetadata>> ListAsync(
        string contextId,
        IReadOnlySet<string>? namespaces,
        CancellationToken cancellationToken = default)
    {
        EnsureEnabled();
        var normalizedContext = NormalizeContextId(contextId);
        var normalizedNamespaces = namespaces?
            .Select(NormalizeNamespace)
            .ToHashSet(StringComparer.Ordinal);
        if (normalizedNamespaces is { Count: 0 }) return [];
        if (snapshots is not null)
        {
            return await snapshots.ListSecretsAsync(
                normalizedContext,
                normalizedNamespaces,
                cancellationToken);
        }

        await using var database = await databaseFactory.CreateDbContextAsync(
            cancellationToken);
        var query = database.VaultSecrets.AsNoTracking()
            .Where(secret => secret.ContextId == normalizedContext);
        if (normalizedNamespaces is not null)
        {
            query = query.Where(secret => normalizedNamespaces.Contains(
                secret.Namespace));
        }
        return await query
            .OrderBy(secret => secret.Name)
            .Select(secret => new VaultSecretMetadata(
                secret.Name,
                secret.Namespace,
                secret.ContextId,
                secret.OwnerSubject,
                secret.UpdatedAtUtc,
                secret.UpdatedBy,
                true))
            .ToArrayAsync(cancellationToken);
    }

    public async Task<VaultSecretMetadata> PutAsync(
        string name,
        string value,
        string updatedBy,
        CancellationToken cancellationToken = default) =>
        await PutAsync(
            name,
            value,
            updatedBy,
            GlobalContextId,
            cancellationToken);

    public async Task<VaultSecretMetadata> PutAsync(
        string name,
        string value,
        string updatedBy,
        string contextId,
        CancellationToken cancellationToken = default)
    {
        EnsureEnabled();
        var normalized = NormalizeName(name);
        var normalizedContext = NormalizeContextId(contextId);
        var secretNamespace = GetNamespace(normalized);
        if (string.IsNullOrWhiteSpace(value))
            throw new ArgumentException("Secret value cannot be empty.", nameof(value));
        if (value.Length > 16_384)
            throw new ArgumentException("Secret value exceeds the 16 KiB limit.", nameof(value));
        if (string.IsNullOrWhiteSpace(updatedBy))
            throw new ArgumentException("Updated-by is required.", nameof(updatedBy));

        await using var database = await databaseFactory.CreateDbContextAsync(
            cancellationToken);
        var item = await database.VaultSecrets
            .SingleOrDefaultAsync(secret => secret.Name == normalized
                && secret.ContextId == normalizedContext,
                cancellationToken);
        var now = DateTime.UtcNow;
        var aad = Aad(normalized, secretNamespace, normalizedContext);
        var ciphertext = await keyVault.EncryptAsync(
            KeyName,
            value,
            aad,
            cancellationToken);

        if (item is null)
        {
            item = new VaultSecret
            {
                Name = normalized,
                Namespace = secretNamespace,
                ContextId = normalizedContext,
                OwnerSubject = NormalizeSubject(updatedBy),
            };
            database.VaultSecrets.Add(item);
        }

        item.Ciphertext = ciphertext;
        item.AadJson = JsonSerializer.Serialize(aad);
        item.UpdatedAtUtc = now;
        item.UpdatedBy = NormalizeSubject(updatedBy);
        await database.SaveChangesAsync(cancellationToken);
        if (snapshots is not null)
        {
            await snapshots.InvalidateSecretAsync(
                normalized,
                normalizedContext,
                cancellationToken);
        }
        return ToMetadata(item);
    }

    public async Task<bool> DeleteAsync(
        string name,
        CancellationToken cancellationToken = default) =>
        await DeleteAsync(name, GlobalContextId, cancellationToken);

    public async Task<bool> DeleteAsync(
        string name,
        string contextId,
        CancellationToken cancellationToken = default)
    {
        EnsureEnabled();
        var normalized = NormalizeName(name);
        var normalizedContext = NormalizeContextId(contextId);
        await using var database = await databaseFactory.CreateDbContextAsync(
            cancellationToken);
        var deleted = await database.VaultSecrets
            .Where(secret => secret.Name == normalized
                && secret.ContextId == normalizedContext)
            .ExecuteDeleteAsync(cancellationToken);
        if (deleted > 0 && snapshots is not null)
        {
            await snapshots.InvalidateSecretAsync(
                normalized,
                normalizedContext,
                cancellationToken);
        }
        return deleted > 0;
    }

    private void EnsureEnabled()
    {
        if (!options.Enabled)
            throw new InvalidOperationException(
                "Enable Sufficit:Vault before using named secrets.");
    }

    public static string NormalizeName(string name)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(name);
        var normalized = name.Trim().ToLowerInvariant();
        if (normalized.Length > 128
            || normalized.Contains("..", StringComparison.Ordinal)
            || normalized.StartsWith('/')
            || normalized.EndsWith('/')
            || normalized.Contains("//", StringComparison.Ordinal)
            || !normalized.Contains('/', StringComparison.Ordinal)
            || normalized.Any(character =>
                !((character is >= 'a' and <= 'z')
                  || (character is >= '0' and <= '9')
                  || character is '/' or '-' or '_' or '.')))
        {
            throw new ArgumentException(
                "Secret name must be a safe logical path of at most 128 characters.",
                nameof(name));
        }

        return normalized;
    }

    public static string NormalizeContextId(string contextId)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(contextId);
        var normalized = contextId.Trim().ToLowerInvariant();
        if (normalized.Length > IdentityDatabaseSchema.VaultSecretContextLength
            || normalized.Any(character =>
                !((character is >= 'a' and <= 'z')
                  || (character is >= '0' and <= '9')
                  || character is '-' or '_' or '.')))
        {
            throw new ArgumentException(
                "Secret context must be a safe identifier of at most 64 characters.",
                nameof(contextId));
        }
        return normalized;
    }

    public static string NormalizeNamespace(string @namespace)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(@namespace);
        var normalized = @namespace.Trim().ToLowerInvariant();
        if (normalized.Length > IdentityDatabaseSchema.VaultSecretNamespaceLength
            || normalized.Any(character =>
                !((character is >= 'a' and <= 'z')
                  || (character is >= '0' and <= '9')
                  || character is '-' or '_' or '.')))
        {
            throw new ArgumentException(
                "Secret namespace must be a safe identifier of at most 64 characters.",
                nameof(@namespace));
        }
        return normalized;
    }

    public static string GetNamespace(string normalizedName) =>
        NormalizeNamespace(normalizedName.Split('/', 2)[0]);

    private static string NormalizeSubject(string subject)
    {
        var normalized = subject.Trim();
        return normalized[..Math.Min(
            normalized.Length,
            IdentityDatabaseSchema.VaultSecretOwnerLength)];
    }

    private static VaultSecretMetadata ToMetadata(VaultSecret secret) =>
        new(
            secret.Name,
            secret.Namespace,
            secret.ContextId,
            secret.OwnerSubject,
            secret.UpdatedAtUtc,
            secret.UpdatedBy,
            true);

    private static IReadOnlyDictionary<string, string> Aad(
        string name,
        string @namespace,
        string contextId) =>
        new Dictionary<string, string>(StringComparer.Ordinal)
        {
            ["scope"] = KeyName,
            ["name"] = name,
            ["namespace"] = @namespace,
            ["context_id"] = contextId,
        };

    private static IReadOnlyDictionary<string, string> ReadAad(VaultSecret secret) =>
        ReadAad(new VaultSecretSnapshotEntry(
            secret.Name,
            secret.Namespace,
            secret.ContextId,
            secret.OwnerSubject,
            secret.Ciphertext,
            secret.AadJson,
            secret.UpdatedAtUtc,
            secret.UpdatedBy));

    private static IReadOnlyDictionary<string, string> ReadAad(
        VaultSecretSnapshotEntry secret)
    {
        if (!string.IsNullOrWhiteSpace(secret.AadJson))
        {
            var parsed = JsonSerializer.Deserialize<Dictionary<string, string>>(
                secret.AadJson);
            if (parsed is not null
                && parsed.TryGetValue("scope", out var scope)
                && string.Equals(scope, KeyName, StringComparison.Ordinal)
                && parsed.TryGetValue("name", out var name)
                && string.Equals(name, secret.Name, StringComparison.Ordinal))
            {
                var hasContext = parsed.TryGetValue(
                    "context_id",
                    out var aadContext);
                var hasNamespace = parsed.TryGetValue(
                    "namespace",
                    out var aadNamespace);
                if (hasContext || hasNamespace)
                {
                    if (hasContext
                        && hasNamespace
                        && string.Equals(
                            aadContext,
                            secret.ContextId,
                            StringComparison.Ordinal)
                        && string.Equals(
                            aadNamespace,
                            secret.Namespace,
                            StringComparison.Ordinal))
                    {
                        return parsed;
                    }

                    throw new CryptographicException(
                        "Named-secret AAD does not match its persisted context or namespace.");
                }

                if (string.Equals(
                        secret.ContextId,
                        GlobalContextId,
                        StringComparison.Ordinal))
                {
                    return parsed;
                }
            }
        }

        // Compatibility for the first named-secret schema, whose AAD was not
        // persisted by every writer and contained only scope + name.
        if (!string.Equals(
                secret.ContextId,
                GlobalContextId,
                StringComparison.Ordinal))
        {
            throw new CryptographicException(
                "Legacy named-secret AAD is accepted only in the global context.");
        }
        return new Dictionary<string, string>(StringComparer.Ordinal)
        {
            ["scope"] = KeyName,
            ["name"] = secret.Name,
        };
    }
}
