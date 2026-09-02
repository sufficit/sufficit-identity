using Sufficit.Identity.Management.Vault;

namespace Sufficit.Identity.Vault;

/// <summary>
/// Composes the user-managed Vault with subject-bound named secrets used by
/// integrations. OAuth handshake state is deliberately omitted: it is transient
/// protocol material, not a credential the user can act on.
/// </summary>
public sealed class UserVaultOverviewService(
    IUserVaultService personalSecrets,
    IVaultNamedSecretStore namedSecrets) : IUserVaultOverviewService
{
    private const string PersonalNamespace =
        UserVaultPersonalSecretService.PersonalNamespace;
    private const string PersonalContextPrefix =
        UserVaultPersonalSecretService.PersonalContextPrefix;
    private const string OAuthPendingPrefix = "integrations/oauth/pending/";
    private const string OAuthTokenPrefix = "integrations/oauth/tokens/";

    public async Task<UserVaultOverview> GetAsync(
        string ownerSubject,
        CancellationToken cancellationToken = default)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(ownerSubject);
        var owner = ownerSubject.Trim();
        var context = VaultBackedSecretStore.NormalizeContextId(
            PersonalContextPrefix + owner.ToLowerInvariant());

        var personalTask = personalSecrets.ListAsync(
            owner,
            PersonalNamespace,
            cancellationToken);
        var namedTask = namedSecrets.ListAsync(
            context,
            namespaces: null,
            cancellationToken);
        await Task.WhenAll(personalTask, namedTask);
        var personal = await personalTask;
        var named = await namedTask;

        // Both lists now come from the same table, so the reserved namespace is
        // what keeps the two UI sections disjoint: without this filter a secret
        // the user typed would also be reported as a connected credential.
        var managed = named
            .Where(item => !UserVaultPersonalSecretService.IsPersonal(item.Namespace)
                && !item.Name.StartsWith(
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

        return new UserVaultOverview(personal, managed);
    }

    private static string? ProviderFrom(string name)
    {
        if (!name.StartsWith(OAuthTokenPrefix, StringComparison.Ordinal))
            return null;

        var provider = name[OAuthTokenPrefix.Length..];
        return provider.Length > 0 && !provider.Contains('/')
            ? provider
            : null;
    }
}
