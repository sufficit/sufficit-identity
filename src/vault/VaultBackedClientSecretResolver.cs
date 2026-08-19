using Sufficit.Identity.Management.Provisioning;

namespace Sufficit.Identity.Vault;

/// <summary>
/// <see cref="IClientSecretResolver"/> backed by the internal vault. Resolves
/// a secret reference (the <c>SecretReference</c> from a provisioning manifest).
/// New manifests use a logical named-secret path in the central Vault; the
/// encrypted-ciphertext form remains supported for backwards compatibility.
/// </summary>
/// <remarks>
/// <para>
/// Logical paths are resolved inside Identity and are never exposed by the
/// management API. The legacy ciphertext form is decrypted with
/// <see cref="IKeyVault"/>.
/// </para>
/// <para>
/// This replaces the <c>MissingClientSecretResolver</c> stub so provisioning of
/// confidential clients actually works out-of-the-box (closes M1, eval).
/// </para>
/// </remarks>
public sealed class VaultBackedClientSecretResolver(
    IKeyVault keyVault,
    IVaultNamedSecretStore? namedSecrets = null)
    : IClientSecretResolver
{
    private const string ClientSecretsKeyName = "client-secrets";
    private const string GlobalContextId = "global";

    public async ValueTask<string> ResolveAsync(
        string reference,
        CancellationToken cancellationToken = default)
    {
        if (string.IsNullOrWhiteSpace(reference))
        {
            throw new ClientSecretResolutionException();
        }

        // Provisioning manifests intentionally carry only a logical path. A
        // missing path fails closed below; it must never be interpreted as a
        // plaintext credential in production.
        if (namedSecrets is not null && LooksLikeLogicalPath(reference))
        {
            var namedValue = await namedSecrets.GetSecretAsync(
                reference,
                GlobalContextId,
                cancellationToken);
            if (!string.IsNullOrWhiteSpace(namedValue))
            {
                return namedValue;
            }
        }

        // The reference is ciphertext (real vault) or a pass-through marker
        // blob (disabled vault). Either way, DecryptStringAsync round-trips it.
        // If the reference looks like plaintext (no vault marker prefix and not
        // a v1. ciphertext), the vault throws — but with PassThrough, anything
        // without the "pt1." prefix also throws. To support the dev/migration
        // case where the reference IS the plaintext secret, we fall back to
        // returning the reference as-is when decryption fails AND the vault is
        // in pass-through mode.
        try
        {
            return await keyVault.DecryptStringAsync(reference, null, cancellationToken);
        }
        catch (FormatException) when (
            keyVault is IKeyVaultPlaintextReferenceCompatibility
            {
                AcceptsPlaintextClientSecretReferences: true,
            })
        {
            // Only the explicitly marked Development compatibility backend
            // may interpret a raw reference as plaintext.
            return reference;
        }
        catch (FormatException exception)
        {
            throw new ClientSecretResolutionException(exception);
        }
    }

    /// <summary>
    /// Encrypts a plaintext client secret into a vault reference (the inverse
    /// of <see cref="ResolveAsync"/>). Used by tooling/admin to store a secret
    /// so it can later be referenced in a provisioning manifest.
    /// </summary>
    public async Task<string> StoreAsync(
        string plaintextSecret,
        CancellationToken cancellationToken = default)
    {
        return await keyVault.EncryptAsync(
            ClientSecretsKeyName,
            plaintextSecret,
            null,
            cancellationToken);
    }

    private static bool LooksLikeLogicalPath(string reference) =>
        reference.Contains('/', StringComparison.Ordinal)
        && !reference.Contains("..", StringComparison.Ordinal)
        && reference.All(character =>
            character is >= 'a' and <= 'z'
            or >= 'A' and <= 'Z'
            or >= '0' and <= '9'
            or '/' or '-' or '_' or '.');
}
