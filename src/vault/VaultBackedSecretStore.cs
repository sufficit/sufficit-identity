using System.Text.Json;
using Microsoft.EntityFrameworkCore;
using Sufficit.Identity.Core.Data;
using Sufficit.Identity.Core.Entities;

namespace Sufficit.Identity.Vault;

/// <summary>Metadata returned by the named-secret administration surface.</summary>
public sealed record VaultSecretMetadata(
    string Name,
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

    Task<VaultSecretMetadata> PutAsync(
        string name,
        string value,
        string updatedBy,
        CancellationToken cancellationToken = default);

    Task<bool> DeleteAsync(
        string name,
        CancellationToken cancellationToken = default);
}

public sealed class VaultBackedSecretStore(
    IDbContextFactory<AppDbContext> databaseFactory,
    IKeyVault keyVault,
    VaultOptions options) : IVaultNamedSecretStore, ISecretStore
{
    private const string KeyName = "named-secrets";

    public async Task<string?> GetSecretAsync(
        string name,
        CancellationToken cancellationToken = default)
    {
        EnsureEnabled();
        var normalized = NormalizeName(name);
        await using var database = await databaseFactory.CreateDbContextAsync(
            cancellationToken);
        var item = await database.VaultSecrets.AsNoTracking()
            .SingleOrDefaultAsync(secret => secret.Name == normalized,
                cancellationToken);
        if (item is null) return null;

        return await keyVault.DecryptStringAsync(
            item.Ciphertext,
            Aad(normalized),
            cancellationToken);
    }

    public async Task<IReadOnlyList<VaultSecretMetadata>> ListAsync(
        CancellationToken cancellationToken = default)
    {
        EnsureEnabled();
        await using var database = await databaseFactory.CreateDbContextAsync(
            cancellationToken);
        return await database.VaultSecrets.AsNoTracking()
            .OrderBy(secret => secret.Name)
            .Select(secret => new VaultSecretMetadata(
                secret.Name,
                secret.UpdatedAtUtc,
                secret.UpdatedBy,
                true))
            .ToArrayAsync(cancellationToken);
    }

    public async Task<VaultSecretMetadata> PutAsync(
        string name,
        string value,
        string updatedBy,
        CancellationToken cancellationToken = default)
    {
        EnsureEnabled();
        var normalized = NormalizeName(name);
        if (string.IsNullOrWhiteSpace(value))
            throw new ArgumentException("Secret value cannot be empty.", nameof(value));
        if (value.Length > 16_384)
            throw new ArgumentException("Secret value exceeds the 16 KiB limit.", nameof(value));
        if (string.IsNullOrWhiteSpace(updatedBy))
            throw new ArgumentException("Updated-by is required.", nameof(updatedBy));

        await using var database = await databaseFactory.CreateDbContextAsync(
            cancellationToken);
        var item = await database.VaultSecrets
            .SingleOrDefaultAsync(secret => secret.Name == normalized,
                cancellationToken);
        var now = DateTime.UtcNow;
        var ciphertext = await keyVault.EncryptAsync(
            KeyName,
            value,
            Aad(normalized),
            cancellationToken);

        if (item is null)
        {
            item = new VaultSecret { Name = normalized };
            database.VaultSecrets.Add(item);
        }

        item.Ciphertext = ciphertext;
        item.AadJson = JsonSerializer.Serialize(Aad(normalized));
        item.UpdatedAtUtc = now;
        item.UpdatedBy = updatedBy.Trim()[..Math.Min(updatedBy.Trim().Length, 128)];
        await database.SaveChangesAsync(cancellationToken);
        return new(normalized, now, item.UpdatedBy, true);
    }

    public async Task<bool> DeleteAsync(
        string name,
        CancellationToken cancellationToken = default)
    {
        EnsureEnabled();
        var normalized = NormalizeName(name);
        await using var database = await databaseFactory.CreateDbContextAsync(
            cancellationToken);
        var deleted = await database.VaultSecrets
            .Where(secret => secret.Name == normalized)
            .ExecuteDeleteAsync(cancellationToken);
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
        var normalized = name.Trim();
        if (normalized.Length > 128
            || normalized.Contains("..", StringComparison.Ordinal)
            || normalized.Any(character =>
                !(char.IsLetterOrDigit(character)
                  || character is '/' or '-' or '_' or '.')))
        {
            throw new ArgumentException(
                "Secret name must be a safe logical path of at most 128 characters.",
                nameof(name));
        }

        return normalized;
    }

    private static IReadOnlyDictionary<string, string> Aad(string name) =>
        new Dictionary<string, string>(StringComparer.Ordinal)
        {
            ["scope"] = KeyName,
            ["name"] = name,
        };
}
