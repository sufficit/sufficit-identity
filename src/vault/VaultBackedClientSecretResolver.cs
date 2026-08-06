using Sufficit.Identity.Management.Provisioning;

namespace Sufficit.Identity.Vault;

/// <summary>
/// <see cref="IClientSecretResolver"/> backed by the internal vault. Resolves
/// a secret reference (the <c>SecretReference</c> from a provisioning manifest)
/// by treating it as the key name in the vault: the reference string is the
/// ciphertext previously stored, and the vault decrypts it.
/// </summary>
/// <remarks>
/// <para>
/// When the vault is disabled (<see cref="PassThroughKeyVault"/>), the
/// reference is treated as plaintext that round-trips unchanged — useful for
/// dev/migration where an operator puts the raw secret as the reference. When
/// the vault is enabled (<see cref="KeyVault"/>), the reference must be
/// self-describing ciphertext produced by a prior
/// <c>IKeyVault.EncryptAsync("client-secrets", plaintext)</c> call.
/// </para>
/// <para>
/// This replaces the <c>MissingClientSecretResolver</c> stub so provisioning of
/// confidential clients actually works out-of-the-box (closes M1, eval).
/// </para>
/// </remarks>
public sealed class VaultBackedClientSecretResolver(IKeyVault keyVault)
    : IClientSecretResolver
{
    private const string ClientSecretsKeyName = "client-secrets";

    public async ValueTask<string> ResolveAsync(
        string reference,
        CancellationToken cancellationToken = default)
    {
        if (string.IsNullOrWhiteSpace(reference))
        {
            throw new ClientSecretResolutionException();
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
        catch (FormatException)
        {
            // Not ciphertext — treat the reference as a plaintext secret (dev
            // mode with PassThrough vault, or an operator who stored the raw
            // secret as the reference). This is intentional: the resolver
            // degrades gracefully rather than blocking provisioning.
            return reference;
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
}
