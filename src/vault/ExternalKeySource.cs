namespace Sufficit.Identity.Vault;

/// <summary>
/// Provider contract implemented by a deployment-specific KMS/HSM adapter.
/// Implementations must perform the private unwrap operation remotely or in
/// protected hardware and must not persist KEK material in the identity DB.
/// </summary>
public interface IVaultExternalKeyEncryptionProvider
{
    /// <summary>Stable key/version URI reported by the remote provider.</summary>
    string KeyIdentifier { get; }

    byte[] Wrap(ReadOnlyMemory<byte> plaintextKey);

    byte[] Unwrap(ReadOnlyMemory<byte> wrappedKey);
}

internal sealed class ExternalKeySource : IVaultKeyEncryptionKeySource
{
    private readonly IVaultExternalKeyEncryptionProvider _provider;

    public ExternalKeySource(
        IVaultExternalKeyEncryptionProvider provider,
        VaultOptions options)
    {
        _provider = provider;
        if (string.IsNullOrWhiteSpace(_provider.KeyIdentifier))
        {
            throw new InvalidOperationException(
                "The external vault KEK provider returned an empty key identifier.");
        }

        if (!string.IsNullOrWhiteSpace(options.ExternalKeyIdentifier)
            && !string.Equals(
                options.ExternalKeyIdentifier,
                _provider.KeyIdentifier,
                StringComparison.Ordinal))
        {
            throw new InvalidOperationException(
                $"The external vault KEK identifier '{_provider.KeyIdentifier}' does not match the configured identifier.");
        }
    }

    public string KeyIdentifier => _provider.KeyIdentifier;

    public byte[] Wrap(ReadOnlyMemory<byte> dek) => _provider.Wrap(dek);

    public byte[] Unwrap(ReadOnlyMemory<byte> wrappedDek) =>
        _provider.Unwrap(wrappedDek);
}
