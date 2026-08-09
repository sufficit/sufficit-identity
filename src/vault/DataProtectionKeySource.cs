using Microsoft.AspNetCore.DataProtection;

namespace Sufficit.Identity.Vault;

/// <summary>
/// Contract for the vault's wrapping-key authority. A KMS/HSM implementation
/// can replace the compatibility Data Protection implementation without
/// changing <see cref="KeyVault"/> or ciphertext format.
/// </summary>
public interface IVaultKeyEncryptionKeySource
{
    /// <summary>Stable, non-secret identifier used in readiness logs.</summary>
    string KeyIdentifier { get; }

    byte[] Wrap(ReadOnlyMemory<byte> dek);
    byte[] Unwrap(ReadOnlyMemory<byte> wrappedDek);
}

/// <summary>
/// Compatibility <c>KEK</c> source backed by ASP.NET Core Data Protection.
/// Its shared key ring is persisted in the identity DB but must be encrypted
/// with the dedicated vault certificate outside Development. This preserves
/// existing wrapped DEKs while separating key-ring protection from token
/// signing.
/// </summary>
internal sealed class DataProtectionKeySource : IVaultKeyEncryptionKeySource
{
    private readonly IDataProtector _protector;

    public DataProtectionKeySource(
        IDataProtectionProvider dataProtectionProvider,
        VaultOptions options)
    {
        _protector = dataProtectionProvider.CreateProtector(options.DataProtectionPurpose);
    }

    public string KeyIdentifier => "dataprotection";

    /// <summary>Wraps (encrypts) a DEK under the KEK.</summary>
    public byte[] Wrap(ReadOnlyMemory<byte> dek) => _protector.Protect(dek.ToArray());

    /// <summary>Unwraps (decrypts) a wrapped DEK.</summary>
    public byte[] Unwrap(ReadOnlyMemory<byte> wrappedDek) => _protector.Unprotect(wrappedDek.ToArray());
}
