using System.Security.Cryptography;
using Microsoft.AspNetCore.WebUtilities;
using Microsoft.IdentityModel.Tokens;
using Sufficit.Identity.Vault;

namespace Sufficit.Identity.STS.Vault;

/// <summary>
/// IdentityModel key facade for an RSA key whose private operation is
/// delegated to <see cref="IKeyVault"/>. No private key bytes are present in
/// this object; <see cref="HasPrivateKey"/> means that the vault can perform
/// the operation remotely from the caller's point of view.
/// </summary>
public sealed class VaultSigningSecurityKey : AsymmetricSecurityKey
{
    private readonly string _keyId;

    public VaultSigningSecurityKey(VaultSigningKey descriptor, IKeyVault keyVault)
    {
        ArgumentNullException.ThrowIfNull(descriptor);
        ArgumentNullException.ThrowIfNull(keyVault);
        KeyName = descriptor.KeyName;
        KeyVersion = descriptor.KeyVersion;
        PublicJwk = descriptor.PublicJwk;
        _keyId = descriptor.KeyId;
        CryptoProviderFactory = new CryptoProviderFactory
        {
            CustomCryptoProvider = new VaultCryptoProvider(keyVault),
            CacheCustomProviders = false,
            CacheSignatureProviders = false,
        };
    }

    public string KeyName { get; }

    public int KeyVersion { get; }

    public string PublicJwk { get; }

    /// <summary>RSA-3072 or P-256, by the version's key family (A6).</summary>
    public override int KeySize =>
        Sufficit.Identity.Vault.SigningAlgorithms.IsEc(PublicJwk) ? 256 : 3072;

    [Obsolete("Use PrivateKeyStatus instead.")]
    public override bool HasPrivateKey => true;

    public override PrivateKeyStatus PrivateKeyStatus => PrivateKeyStatus.Exists;

    public override string KeyId => _keyId;
}

internal sealed class VaultCryptoProvider : ICryptoProvider
{
    private readonly IKeyVault _keyVault;

    public VaultCryptoProvider(IKeyVault keyVault) => _keyVault = keyVault;

    public bool IsSupportedAlgorithm(string algorithm, params object[] args)
    {
        // A6: every algorithm a vault signing version can carry (RS256, PS256,
        // ES256). The signature bytes themselves always come from the vault's
        // SignAsync, which follows the version's embedded algorithm.
        return (string.Equals(algorithm, SecurityAlgorithms.RsaSha256, StringComparison.Ordinal)
                || string.Equals(algorithm, SecurityAlgorithms.RsaSsaPssSha256, StringComparison.Ordinal)
                || string.Equals(algorithm, SecurityAlgorithms.EcdsaSha256, StringComparison.Ordinal))
            && args is not null
            && args.OfType<VaultSigningSecurityKey>().Any();
    }

    public object Create(string algorithm, params object[] args)
    {
        if (!IsSupportedAlgorithm(algorithm, args))
        {
            throw new NotSupportedException($"Vault crypto provider does not support '{algorithm}'.");
        }

        var key = args.OfType<VaultSigningSecurityKey>().Single();
        var willCreateSignatures = args.OfType<bool>().FirstOrDefault();
        return new VaultSignatureProvider(key, algorithm, willCreateSignatures, _keyVault);
    }

    public void Release(object cryptoInstance)
    {
        if (cryptoInstance is IDisposable disposable)
        {
            disposable.Dispose();
        }
    }
}

internal sealed class VaultSignatureProvider : SignatureProvider
{
    private readonly VaultSigningSecurityKey _key;
    private readonly IKeyVault _keyVault;
    private bool _disposed;

    public VaultSignatureProvider(
        VaultSigningSecurityKey key,
        string algorithm,
        bool willCreateSignatures,
        IKeyVault keyVault)
        : base(key, algorithm)
    {
        _key = key;
        _keyVault = keyVault;
        WillCreateSignatures = willCreateSignatures;
    }

    public override byte[] Sign(byte[] input)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        ArgumentNullException.ThrowIfNull(input);
        var encoded = _keyVault.SignAsync(
                _key.KeyName,
                _key.KeyVersion,
                input)
            .GetAwaiter()
            .GetResult();
        var separator = encoded.LastIndexOf('.');
        if (separator < 0 || separator == encoded.Length - 1)
        {
            throw new CryptographicException("Vault returned an invalid signature envelope.");
        }

        return WebEncoders.Base64UrlDecode(encoded[(separator + 1)..]);
    }

    public override bool Sign(
        ReadOnlySpan<byte> data,
        Span<byte> destination,
        out int bytesWritten)
    {
        var signature = Sign(data.ToArray());
        if (destination.Length < signature.Length)
        {
            bytesWritten = 0;
            return false;
        }

        signature.CopyTo(destination);
        bytesWritten = signature.Length;
        return true;
    }

    public override bool Verify(byte[] input, byte[] signature)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        ArgumentNullException.ThrowIfNull(input);
        ArgumentNullException.ThrowIfNull(signature);
        return _keyVault.VerifyAsync(
                _key.KeyName,
                _key.KeyVersion,
                input,
                signature)
            .GetAwaiter()
            .GetResult();
    }

    protected override void Dispose(bool disposing)
    {
        _disposed = true;
    }
}
