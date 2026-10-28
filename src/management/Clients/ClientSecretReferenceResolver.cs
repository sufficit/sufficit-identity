using Sufficit.Identity.Management.Authorization;
using Sufficit.Identity.Management.Vault;

namespace Sufficit.Identity.Management.Clients;

/// <summary>
/// Turns a <see cref="ManagementClientSecretReference"/> into the secret it
/// names, for the one moment the client manager needs to hash it.
/// </summary>
public interface IManagementClientSecretReferenceResolver
{
    Task<string> ResolveAsync(
        ManagementClientSecretReference reference,
        ManagementRequestContext context,
        CancellationToken cancellationToken = default);
}

/// <summary>
/// Resolves through the Management Vault service, so binding a vault secret to
/// a client is authorized exactly like reading it: the operator needs
/// <c>identity.secrets.resolve</c> and the namespace grant, and the resolution
/// is journaled by the Vault service. An operator cannot turn a secret they
/// may not read into a credential.
/// </summary>
internal sealed class VaultClientSecretReferenceResolver(
    IVaultSecretsManagementService vault) : IManagementClientSecretReferenceResolver
{
    public async Task<string> ResolveAsync(
        ManagementClientSecretReference reference,
        ManagementRequestContext context,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(reference);
        if (string.IsNullOrWhiteSpace(reference.Name))
        {
            throw new ManagementValidationException(
                "client_secret_reference_invalid",
                "secretReference.name is required.",
                "secretReference");
        }

        ResolvedManagementVaultSecret? resolved;
        try
        {
            resolved = await vault.ResolveAsync(
                reference.Name.Trim(),
                reference.EffectiveContextId,
                context,
                cancellationToken);
        }
        catch (ArgumentException)
        {
            // Name or context outside the named-secret grammar.
            throw new ManagementValidationException(
                "client_secret_reference_invalid",
                "secretReference does not name a vault secret.",
                "secretReference");
        }

        if (resolved is null)
        {
            throw new ManagementValidationException(
                "client_secret_reference_not_found",
                "secretReference does not name an existing vault secret.",
                "secretReference");
        }

        if (resolved.Status is VaultSecretStatus.Expired
            || string.IsNullOrEmpty(resolved.Value))
        {
            throw new ManagementValidationException(
                "client_secret_reference_expired",
                "The referenced vault secret has expired or has no value.",
                "secretReference");
        }

        return resolved.Value;
    }
}
