using System.Text.Json;
using Microsoft.EntityFrameworkCore;
using Sufficit.Identity.Core.Data;
using Sufficit.Identity.Core.Entities;
using Sufficit.Identity.Management.Vault;

namespace Sufficit.Identity.Vault;

/// <summary>
/// User-owned Vault boundary. The owner subject is supplied by the authenticated
/// caller and is included in every query and encryption AAD value.
/// </summary>
public sealed class UserVaultPersonalSecretService(
    IDbContextFactory<AppDbContext> databaseFactory,
    IKeyVault keyVault,
    VaultOptions options) : IUserVaultService
{
    private const string KeyName = "personal-secrets";

    public async Task<IReadOnlyList<UserVaultSecretMetadata>> ListAsync(
        string ownerSubject,
        string @namespace,
        CancellationToken cancellationToken = default)
    {
        EnsureEnabled();
        var owner = NormalizeOwner(ownerSubject);
        var scope = NormalizeNamespace(@namespace);
        await using var database = await databaseFactory.CreateDbContextAsync(cancellationToken);
        return await database.VaultPersonalSecrets.AsNoTracking()
            .Where(secret => secret.OwnerSubject == owner && secret.Namespace == scope)
            .OrderBy(secret => secret.Name)
            .Select(secret => new UserVaultSecretMetadata(secret.Namespace, secret.Name,
                secret.UpdatedAtUtc, secret.UpdatedBy, true))
            .ToArrayAsync(cancellationToken);
    }

    public async Task<UserVaultSecretMetadata?> GetAsync(
        string ownerSubject, string @namespace, string name,
        CancellationToken cancellationToken = default)
    {
        EnsureEnabled();
        var owner = NormalizeOwner(ownerSubject);
        var scope = NormalizeNamespace(@namespace);
        var normalized = VaultBackedSecretStore.NormalizeName(name);
        await using var database = await databaseFactory.CreateDbContextAsync(cancellationToken);
        var item = await database.VaultPersonalSecrets.AsNoTracking()
            .SingleOrDefaultAsync(secret => secret.OwnerSubject == owner
                && secret.Namespace == scope && secret.Name == normalized,
                cancellationToken);
        return item is null ? null : new(item.Namespace, item.Name,
            item.UpdatedAtUtc, item.UpdatedBy, true);
    }

    public async Task<UserVaultSecretMetadata> PutAsync(
        string ownerSubject, string @namespace, string name,
        SaveUserVaultSecret command,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(command);
        EnsureEnabled();
        var owner = NormalizeOwner(ownerSubject);
        var scope = NormalizeNamespace(@namespace);
        var normalized = VaultBackedSecretStore.NormalizeName(name);
        if (string.IsNullOrWhiteSpace(command.Value))
            throw new ArgumentException("Secret value cannot be empty.", nameof(command));
        if (command.Value.Length > 16_384)
            throw new ArgumentException("Secret value exceeds the 16 KiB limit.", nameof(command));

        await using var database = await databaseFactory.CreateDbContextAsync(cancellationToken);
        var item = await database.VaultPersonalSecrets.SingleOrDefaultAsync(secret =>
            secret.OwnerSubject == owner && secret.Namespace == scope
            && secret.Name == normalized, cancellationToken);
        var now = DateTime.UtcNow;
        var ciphertext = await keyVault.EncryptAsync(KeyName, command.Value,
            Aad(owner, scope, normalized), cancellationToken);
        if (item is null)
        {
            item = new VaultPersonalSecret
            {
                OwnerSubject = owner,
                Namespace = scope,
                Name = normalized
            };
            database.VaultPersonalSecrets.Add(item);
        }

        item.Ciphertext = ciphertext;
        item.AadJson = JsonSerializer.Serialize(Aad(owner, scope, normalized));
        item.UpdatedAtUtc = now;
        item.UpdatedBy = owner;
        await database.SaveChangesAsync(cancellationToken);
        return new(scope, normalized, now, owner, true);
    }

    public async Task DeleteAsync(
        string ownerSubject, string @namespace, string name,
        CancellationToken cancellationToken = default)
    {
        EnsureEnabled();
        var owner = NormalizeOwner(ownerSubject);
        var scope = NormalizeNamespace(@namespace);
        var normalized = VaultBackedSecretStore.NormalizeName(name);
        await using var database = await databaseFactory.CreateDbContextAsync(cancellationToken);
        var deleted = await database.VaultPersonalSecrets
            .Where(secret => secret.OwnerSubject == owner && secret.Namespace == scope
                && secret.Name == normalized)
            .ExecuteDeleteAsync(cancellationToken);
        if (deleted is 0)
            throw new KeyNotFoundException("Personal Vault secret was not found.");
    }

    private void EnsureEnabled()
    {
        if (!options.Enabled)
            throw new InvalidOperationException("Enable Sufficit:Vault before using personal secrets.");
    }

    private static string NormalizeOwner(string value)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(value);
        var normalized = value.Trim();
        return normalized.Length <= 255 ? normalized
            : throw new ArgumentException("Owner subject is too long.", nameof(value));
    }

    private static string NormalizeNamespace(string value)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(value);
        var normalized = value.Trim().ToLowerInvariant();
        if (normalized.Length is 0 or > 64 || normalized.Any(character =>
            !(char.IsLetterOrDigit(character) || character is '-' or '_' or '.')))
            throw new ArgumentException("Vault namespace is invalid.", nameof(value));
        return normalized;
    }

    private static IReadOnlyDictionary<string, string> Aad(
        string owner, string @namespace, string name) =>
        new Dictionary<string, string>(StringComparer.Ordinal)
        {
            ["scope"] = KeyName, ["owner"] = owner,
            ["namespace"] = @namespace, ["name"] = name
        };
}
