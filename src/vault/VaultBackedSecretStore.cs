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
    bool HasValue,
    DateTime? ExpiresAtUtc = null);

/// <summary>
/// Explicit resolution outcome so callers can distinguish "absent" (null
/// resolution) from "expired" (metadata present, <see cref="Value"/> null).
/// Expired secrets are never decrypted.
/// </summary>
public sealed record VaultNamedSecretResolution(
    VaultSecretMetadata Metadata,
    string? Value);

/// <summary>
/// Typed vault context: the owner kind (user | tenant | client | global) plus
/// the Guid identifying the owner inside that kind. This is the runtime form
/// of the vaultsecrets (type, contextid) row key, so the same Guid can exist
/// as a user's private context and as a client's system context at once.
///
/// Canonical text form (the only thing string boundaries ever see):
/// <c>global</c>, <c>user-&lt;guid&gt;</c>, <c>tenant-&lt;guid&gt;</c> and a
/// bare <c>&lt;guid&gt;</c> (client). A bare Guid parses as <c>client</c>
/// because every pre-discriminator writer that used a bare Guid was addressing
/// a system context — the storage migration classifies historical rows the
/// same way, so runtime lookups keep finding migrated data.
/// </summary>
public readonly record struct VaultSecretContext(string Type, Guid ContextId)
{
    /// <summary>Parses any historical or current context text into its typed
    /// form. Unrecognized values collapse to the global context, mirroring the
    /// one-way storage migration.</summary>
    public static VaultSecretContext Parse(string contextId)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(contextId);
        var value = contextId.Trim().ToLowerInvariant();
        if (value == VaultBackedSecretStore.GlobalContextId)
            return new VaultSecretContext(
                IdentityDatabaseSchema.VaultSecretTypeGlobal,
                Guid.Empty);
        foreach (var (prefix, type) in Prefixes)
        {
            if (!value.StartsWith(prefix, StringComparison.Ordinal)) continue;
            var rest = value[prefix.Length..];
            return new VaultSecretContext(
                type,
                Guid.TryParse(rest, out var prefixed)
                    ? prefixed
                    : Guid.Empty);
        }

        return Guid.TryParse(value, out var bare)
            ? new VaultSecretContext(IdentityDatabaseSchema.VaultSecretTypeClient, bare)
            : new VaultSecretContext(
                IdentityDatabaseSchema.VaultSecretTypeGlobal,
                Guid.Empty);
    }

    private static readonly (string Prefix, string Type)[] Prefixes =
    [
        (VaultBackedSecretStore.UserContextPrefix, IdentityDatabaseSchema.VaultSecretTypeUser),
        (VaultBackedSecretStore.TenantContextPrefix, IdentityDatabaseSchema.VaultSecretTypeTenant),
        (VaultBackedSecretStore.ClientContextPrefix, IdentityDatabaseSchema.VaultSecretTypeClient),
    ];

    public override string ToString() =>
        Type switch
        {
            IdentityDatabaseSchema.VaultSecretTypeUser =>
                VaultBackedSecretStore.UserContextPrefix + ContextId.ToString("D"),
            IdentityDatabaseSchema.VaultSecretTypeTenant =>
                VaultBackedSecretStore.TenantContextPrefix + ContextId.ToString("D"),
            // The client form is the bare Guid: it is what every historical
            // writer already emitted, so ciphertext AAD and API contracts are
            // byte-identical before and after the discriminator.
            IdentityDatabaseSchema.VaultSecretTypeClient => ContextId.ToString("D"),
            _ => VaultBackedSecretStore.GlobalContextId,
        };
}

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

    /// <summary>Resolves a secret with its metadata. Returns null when the
    /// secret does not exist; an expired secret returns metadata with a null
    /// value so the caller can report the distinction (e.g. 410 vs 404).</summary>
    Task<VaultNamedSecretResolution?> ResolveAsync(
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

    Task<VaultSecretMetadata> PutAsync(
        string name,
        string value,
        string updatedBy,
        string contextId,
        DateTime? expiresAtUtc,
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

    /// <summary>Context prefix marking a per-user private context.</summary>
    public const string UserContextPrefix = "user-";

    /// <summary>Context prefix reserved for the future tenant-credential
    /// sharing model (not implemented yet).</summary>
    public const string TenantContextPrefix = "tenant-";

    /// <summary>Context prefix for per-application (client) system
    /// credentials such as connection strings.</summary>
    public const string ClientContextPrefix = "client-";

    public static readonly VaultSecretContext GlobalContext =
        new(IdentityDatabaseSchema.VaultSecretTypeGlobal, Guid.Empty);

    public async Task<string?> GetSecretAsync(
        string name,
        CancellationToken cancellationToken = default) =>
        await GetSecretAsync(name, GlobalContextId, cancellationToken);

    public async Task<string?> GetSecretAsync(
        string name,
        string contextId,
        CancellationToken cancellationToken = default)
    {
        var resolution = await ResolveAsync(name, contextId, cancellationToken);
        return resolution?.Value;
    }

    public async Task<VaultNamedSecretResolution?> ResolveAsync(
        string name,
        string contextId,
        CancellationToken cancellationToken = default)
    {
        EnsureEnabled();
        var normalized = NormalizeName(name);
        var context = VaultSecretContext.Parse(NormalizeContextId(contextId));
        if (snapshots is not null)
        {
            var snapshot = await snapshots.GetSecretAsync(
                normalized,
                context.ToString(),
                cancellationToken);
            if (snapshot is null) return null;

            return await ResolveEntryAsync(
                ToMetadata(snapshot),
                snapshot.Ciphertext,
                () => ReadAad(snapshot),
                cancellationToken);
        }

        await using var database = await databaseFactory.CreateDbContextAsync(
            cancellationToken);
        var item = await database.VaultSecrets.AsNoTracking()
            .SingleOrDefaultAsync(secret => secret.Name == normalized
                && secret.Type == context.Type
                && secret.ContextId == context.ContextId,
                cancellationToken);
        if (item is null) return null;

        return await ResolveEntryAsync(
            ToMetadata(item),
            item.Ciphertext,
            () => ReadAad(item),
            cancellationToken);
    }

    /// <summary>Expired entries are reported, never decrypted.</summary>
    private async Task<VaultNamedSecretResolution> ResolveEntryAsync(
        VaultSecretMetadata metadata,
        string ciphertext,
        Func<IReadOnlyDictionary<string, string>> aad,
        CancellationToken cancellationToken)
    {
        if (metadata.ExpiresAtUtc is { } expiresAtUtc
            && expiresAtUtc <= DateTime.UtcNow)
        {
            return new VaultNamedSecretResolution(metadata, Value: null);
        }

        var value = await keyVault.DecryptStringAsync(
            ciphertext,
            aad(),
            cancellationToken);
        return new VaultNamedSecretResolution(metadata, value);
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
        var context = VaultSecretContext.Parse(NormalizeContextId(contextId));
        var normalizedNamespaces = namespaces?
            .Select(NormalizeNamespace)
            .ToHashSet(StringComparer.Ordinal);
        if (normalizedNamespaces is { Count: 0 }) return [];
        if (snapshots is not null)
        {
            return await snapshots.ListSecretsAsync(
                context.ToString(),
                normalizedNamespaces,
                cancellationToken);
        }

        await using var database = await databaseFactory.CreateDbContextAsync(
            cancellationToken);
        var query = database.VaultSecrets.AsNoTracking()
            .Where(secret => secret.Type == context.Type
                && secret.ContextId == context.ContextId);
        if (normalizedNamespaces is not null)
        {
            query = query.Where(secret => normalizedNamespaces.Contains(
                secret.Namespace));
        }
        var rows = await query
            .OrderBy(secret => secret.Name)
            .Select(secret => new
            {
                secret.Name,
                secret.Namespace,
                secret.Type,
                secret.ContextId,
                secret.OwnerSubject,
                secret.UpdatedAtUtc,
                secret.UpdatedBy,
                secret.ExpiresAtUtc
            })
            .ToArrayAsync(cancellationToken);
        // Guid → display mapping happens client-side: EF cannot translate the
        // context rendering, and selecting entities would drag the ciphertext
        // column along.
        return rows.Select(secret => new VaultSecretMetadata(
            secret.Name,
            secret.Namespace,
            new VaultSecretContext(secret.Type, secret.ContextId).ToString(),
            ToSubjectString(secret.OwnerSubject),
            secret.UpdatedAtUtc,
            secret.UpdatedBy,
            true,
            secret.ExpiresAtUtc)).ToArray();
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
        CancellationToken cancellationToken = default) =>
        await PutAsync(
            name,
            value,
            updatedBy,
            contextId,
            expiresAtUtc: null,
            cancellationToken);

    public async Task<VaultSecretMetadata> PutAsync(
        string name,
        string value,
        string updatedBy,
        string contextId,
        DateTime? expiresAtUtc,
        CancellationToken cancellationToken = default)
    {
        EnsureEnabled();
        var normalized = NormalizeName(name);
        var context = VaultSecretContext.Parse(NormalizeContextId(contextId));
        var secretNamespace = GetNamespace(normalized);
        if (string.IsNullOrWhiteSpace(value))
            throw new ArgumentException("Secret value cannot be empty.", nameof(value));
        if (value.Length > 16_384)
            throw new ArgumentException("Secret value exceeds the 16 KiB limit.", nameof(value));
        if (string.IsNullOrWhiteSpace(updatedBy))
            throw new ArgumentException("Updated-by is required.", nameof(updatedBy));
        if (expiresAtUtc is { } expiration && expiration <= DateTime.UtcNow)
            throw new ArgumentException(
                "Secret expiration must be in the future.", nameof(expiresAtUtc));

        await using var database = await databaseFactory.CreateDbContextAsync(
            cancellationToken);
        var item = await database.VaultSecrets
            .SingleOrDefaultAsync(secret => secret.Name == normalized
                && secret.Type == context.Type
                && secret.ContextId == context.ContextId,
                cancellationToken);
        var now = DateTime.UtcNow;
        var aad = Aad(normalized, secretNamespace, context.ToString());
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
                Type = context.Type,
                ContextId = context.ContextId,
                // A user context IS its owner: the subject Guid in the key is
                // the user the secrets are private to, regardless of which
                // surface (or operator) created the first row.
                OwnerSubject = context.Type == IdentityDatabaseSchema.VaultSecretTypeUser
                    ? context.ContextId
                    : ToSubjectGuid(updatedBy),
            };
            database.VaultSecrets.Add(item);
        }

        item.Ciphertext = ciphertext;
        item.AadJson = JsonSerializer.Serialize(aad);
        item.ExpiresAtUtc = expiresAtUtc;
        item.UpdatedAtUtc = now;
        item.UpdatedBy = NormalizeSubject(updatedBy);
        await database.SaveChangesAsync(cancellationToken);
        if (snapshots is not null)
        {
            await snapshots.InvalidateSecretAsync(
                normalized,
                context.ToString(),
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
        var context = VaultSecretContext.Parse(NormalizeContextId(contextId));
        await using var database = await databaseFactory.CreateDbContextAsync(
            cancellationToken);
        var deleted = await database.VaultSecrets
            .Where(secret => secret.Name == normalized
                && secret.Type == context.Type
                && secret.ContextId == context.ContextId)
            .ExecuteDeleteAsync(cancellationToken);
        if (deleted > 0 && snapshots is not null)
        {
            await snapshots.InvalidateSecretAsync(
                normalized,
                context.ToString(),
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

    /// <summary>Subject Guid under the same conversion rules as the context:
    /// a textual Guid is kept, a legacy <c>user-</c> prefix is stripped and
    /// anything else collapses to <see cref="Guid.Empty"/>.</summary>
    public static Guid ToSubjectGuid(string subject)
    {
        var value = subject.Trim();
        if (value.StartsWith(UserContextPrefix, StringComparison.Ordinal))
            value = value[UserContextPrefix.Length..];
        return Guid.TryParse(value, out var guid) ? guid : Guid.Empty;
    }

    /// <summary>Display form of a subject Guid; <see cref="Guid.Empty"/> (no
    /// recognizable owner) renders as an empty string.</summary>
    public static string ToSubjectString(Guid subject) =>
        subject == Guid.Empty ? string.Empty : subject.ToString("D");

    private static string NormalizeSubject(string subject)
    {
        var normalized = subject.Trim();
        return normalized[..Math.Min(
            normalized.Length,
            IdentityDatabaseSchema.VaultSecretUpdatedByLength)];
    }

    private static VaultSecretMetadata ToMetadata(VaultSecret secret) =>
        new(
            secret.Name,
            secret.Namespace,
            new VaultSecretContext(secret.Type, secret.ContextId).ToString(),
            ToSubjectString(secret.OwnerSubject),
            secret.UpdatedAtUtc,
            secret.UpdatedBy,
            true,
            secret.ExpiresAtUtc);

    private static VaultSecretMetadata ToMetadata(VaultSecretSnapshotEntry entry) =>
        new(
            entry.Name,
            entry.Namespace,
            entry.ContextId,
            entry.OwnerSubject,
            entry.UpdatedAtUtc,
            entry.UpdatedBy,
            true,
            entry.ExpiresAtUtc);

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
            new VaultSecretContext(secret.Type, secret.ContextId).ToString(),
            ToSubjectString(secret.OwnerSubject),
            secret.Ciphertext,
            secret.AadJson,
            secret.UpdatedAtUtc,
            secret.UpdatedBy,
            secret.ExpiresAtUtc));

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
                    // Contexts compare by Guid so ciphertext written before
                    // the type discriminator (bare-Guid client form, legacy
                    // user-<guid> AAD) keeps authenticating its migrated row;
                    // the discriminator never weakens the name/namespace bind.
                    if (hasContext
                        && hasNamespace
                        && VaultSecretContext.Parse(aadContext ?? string.Empty).ContextId
                            == VaultSecretContext.Parse(secret.ContextId).ContextId
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

                if (VaultSecretContext.Parse(secret.ContextId).ContextId == Guid.Empty)
                {
                    return parsed;
                }
            }
        }

        // Compatibility for the first named-secret schema, whose AAD was not
        // persisted by every writer and contained only scope + name. Only the
        // global (empty-Guid) context accepts that legacy shape.
        if (VaultSecretContext.Parse(secret.ContextId).ContextId != Guid.Empty)
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
