using Sufficit.Identity.Core.Data;
using Sufficit.Identity.Management.Vault;

namespace Sufficit.Identity.Vault;

/// <summary>
/// User-owned Vault boundary. Secrets the user types in the Vault UI are stored
/// as named secrets in that user's own <c>user-&lt;sub&gt;</c> context, which is
/// the same place the personal Vault API and the MCP tools write, so a secret
/// saved in the browser and one saved by a device client land in one inventory.
///
/// This used to own a private <c>vaultpersonalsecrets</c> table. That was a
/// second, parallel design for the same feature and nothing but this class ever
/// reached it, so the storage was merged here and the table dropped.
///
/// Merging creates a hazard the separate tables could not have: the caller
/// chooses the secret name, so a user typing <c>oauth/tokens/google-workspace</c>
/// under <c>integrations</c> would silently overwrite their own connected
/// credential. The defence is structural instead of a blocklist — every
/// user-typed secret is forced under the reserved <see cref="PersonalNamespace"/>
/// root segment, and the named-secret store derives the persisted namespace from
/// that segment, so no caller of this service can address a platform-owned
/// namespace at all. A blocklist would have to enumerate every namespace the
/// platform might claim in the future; the reservation stays correct without
/// being updated.
/// </summary>
public sealed class UserVaultPersonalSecretService(
    IVaultNamedSecretStore store,
    VaultOptions options) : IUserVaultService
{
    /// <summary>
    /// Reserved root segment, and therefore the persisted namespace, of every
    /// secret the user typed themselves. Platform writers own the other
    /// namespaces in the same context — notably <c>integrations</c> for OAuth
    /// tokens and pending handshake state — and are unreachable from here.
    /// </summary>
    public const string PersonalNamespace = "personal";

    /// <summary>Context layout shared with the personal Vault API and MCP tools.</summary>
    public const string PersonalContextPrefix = "user-";

    private const string PersonalPrefix = PersonalNamespace + "/";

    public async Task<IReadOnlyList<UserVaultSecretMetadata>> ListAsync(
        string ownerSubject,
        string @namespace,
        CancellationToken cancellationToken = default)
    {
        EnsureEnabled();
        var owner = NormalizeOwner(ownerSubject);
        EnsurePersonalNamespace(@namespace);
        var items = await store.ListAsync(
            ContextFor(owner),
            new HashSet<string>(StringComparer.Ordinal) { PersonalNamespace },
            cancellationToken);
        return items
            .Where(item => item.Name.StartsWith(
                PersonalPrefix,
                StringComparison.Ordinal))
            .Select(item => new UserVaultSecretMetadata(
                PersonalNamespace,
                ToDisplayName(item.Name),
                item.UpdatedAtUtc,
                item.UpdatedBy,
                true))
            .OrderBy(item => item.Name, StringComparer.Ordinal)
            .ToArray();
    }

    public async Task<UserVaultSecretMetadata?> GetAsync(
        string ownerSubject, string @namespace, string name,
        CancellationToken cancellationToken = default)
    {
        // Filtered from the metadata listing rather than resolved: this contract
        // returns metadata only, and resolving would decrypt the value to throw
        // it away.
        var normalized = ToDisplayName(ToStoredName(name));
        var items = await ListAsync(ownerSubject, @namespace, cancellationToken);
        return items.SingleOrDefault(item => string.Equals(
            item.Name,
            normalized,
            StringComparison.Ordinal));
    }

    public async Task<UserVaultSecretMetadata> PutAsync(
        string ownerSubject, string @namespace, string name,
        SaveUserVaultSecret command,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(command);
        EnsureEnabled();
        var owner = NormalizeOwner(ownerSubject);
        EnsurePersonalNamespace(@namespace);
        var storedName = ToStoredName(name);
        if (string.IsNullOrWhiteSpace(command.Value))
            throw new ArgumentException("Secret value cannot be empty.", nameof(command));
        if (command.Value.Length > 16_384)
            throw new ArgumentException("Secret value exceeds the 16 KiB limit.", nameof(command));

        var metadata = await store.PutAsync(
            storedName,
            command.Value,
            owner,
            ContextFor(owner),
            cancellationToken);
        return new(
            PersonalNamespace,
            ToDisplayName(metadata.Name),
            metadata.UpdatedAtUtc,
            metadata.UpdatedBy,
            true);
    }

    public async Task DeleteAsync(
        string ownerSubject, string @namespace, string name,
        CancellationToken cancellationToken = default)
    {
        EnsureEnabled();
        var owner = NormalizeOwner(ownerSubject);
        EnsurePersonalNamespace(@namespace);
        // Deleting through the same reserved mapping the writer uses is what
        // stops this boundary from removing a connected credential.
        if (!await store.DeleteAsync(
                ToStoredName(name),
                ContextFor(owner),
                cancellationToken))
            throw new KeyNotFoundException("Personal Vault secret was not found.");
    }

    /// <summary>
    /// True when a named secret found in a user context is one the user typed,
    /// as opposed to a credential written by a connected application. This is
    /// the single predicate behind the two sections of the Vault UI, so both
    /// stay disjoint by construction rather than by matching name prefixes.
    /// </summary>
    public static bool IsPersonal(string @namespace) =>
        string.Equals(@namespace, PersonalNamespace, StringComparison.Ordinal);

    /// <summary>
    /// Same context layout the personal Vault API and the MCP tools use.
    /// NormalizeContextId enforces the 64-character column budget, which is the
    /// real limit on how long a subject can be here.
    /// </summary>
    public static string ContextFor(string ownerSubject) =>
        VaultBackedSecretStore.NormalizeContextId(
            PersonalContextPrefix + NormalizeOwner(ownerSubject).ToLowerInvariant());

    /// <summary>
    /// Maps the name the user typed onto the reserved namespace. The prefix is
    /// applied unconditionally so the mapping stays injective: someone typing
    /// <c>personal/x</c> gets <c>personal/personal/x</c> instead of colliding
    /// with someone who typed <c>x</c>.
    /// </summary>
    public static string ToStoredName(string name)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(name);
        var candidate = PersonalPrefix + name.Trim();
        if (candidate.Length > IdentityDatabaseSchema.VaultSecretNameLength)
            throw new ArgumentException(
                "Personal secret name is too long once the reserved "
                + $"'{PersonalNamespace}' prefix is applied; use at most "
                + $"{IdentityDatabaseSchema.VaultSecretNameLength - PersonalPrefix.Length}"
                + " characters.",
                nameof(name));
        return VaultBackedSecretStore.NormalizeName(candidate);
    }

    /// <summary>Inverse of <see cref="ToStoredName"/>, for display and delete.</summary>
    public static string ToDisplayName(string storedName)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(storedName);
        return storedName.StartsWith(PersonalPrefix, StringComparison.Ordinal)
            ? storedName[PersonalPrefix.Length..]
            : storedName;
    }

    private void EnsureEnabled()
    {
        if (!options.Enabled)
            throw new InvalidOperationException("Enable Sufficit:Vault before using personal secrets.");
    }

    /// <summary>
    /// Second layer of the same defence, deliberately loud. The reserved prefix
    /// already makes a platform namespace unreachable, so a caller asking for a
    /// different one is a bug; silently rewriting it to the personal namespace
    /// would hide that bug and leave the caller believing it wrote elsewhere.
    /// </summary>
    private static void EnsurePersonalNamespace(string @namespace)
    {
        var normalized = VaultBackedSecretStore.NormalizeNamespace(@namespace);
        if (!IsPersonal(normalized))
            throw new ArgumentException(
                "User-typed Vault secrets are confined to the "
                + $"'{PersonalNamespace}' namespace; '{normalized}' is reserved "
                + "for credentials written by the platform.",
                nameof(@namespace));
    }

    private static string NormalizeOwner(string value)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(value);
        return value.Trim();
    }
}
