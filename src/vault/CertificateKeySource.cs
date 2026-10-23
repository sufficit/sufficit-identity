using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

namespace Sufficit.Identity.Vault;

/// <summary>
/// A KEK source that can tell whether a wrapped key is already protected by
/// the active KEK, so <c>--rewrap-vault-kek</c> moves only what a retiring
/// KEK still protects (plan C1).
/// </summary>
public interface IVaultRewrappableKeySource : IVaultKeyEncryptionKeySource
{
    /// <summary>True when decrypt-only previous KEKs are configured.</summary>
    bool HasPreviousKeys { get; }

    /// <summary>True when the active KEK alone unwraps <paramref name="wrappedDek"/>.</summary>
    bool IsWrappedByActiveKey(ReadOnlyMemory<byte> wrappedDek);
}

/// <summary>
/// Wraps vault DEKs with a dedicated RSA certificate. The private key remains
/// outside the database and is required only for unwrap operations. Previous
/// certificates (<see cref="VaultOptions.PreviousCertificatePaths"/>) only
/// unwrap, so a KEK rotation never strands a key wrapped before it.
/// </summary>
internal sealed class CertificateKeySource : IVaultRewrappableKeySource, IDisposable
{
    private readonly X509Certificate2 _certificate;
    private readonly IReadOnlyList<X509Certificate2> _previous;

    public CertificateKeySource(
        VaultOptions options,
        ISecretStore? secretStore = null)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(options.CertificatePath);
        _certificate = VaultKeyEncryptionCertificate.Load(options, secretStore);
        try
        {
            _previous = VaultKeyEncryptionCertificate.LoadPrevious(options, secretStore);
        }
        catch
        {
            _certificate.Dispose();
            throw;
        }
    }

    public string KeyIdentifier => $"certificate:{_certificate.Thumbprint}";

    public bool HasPreviousKeys => _previous.Count > 0;

    public byte[] Wrap(ReadOnlyMemory<byte> dek)
    {
        using var rsa = _certificate.GetRSAPublicKey()
            ?? throw new CryptographicException(
                "The vault KEK certificate does not expose an RSA public key.");
        return rsa.Encrypt(dek.Span, RSAEncryptionPadding.OaepSHA256);
    }

    public byte[] Unwrap(ReadOnlyMemory<byte> wrappedDek)
    {
        if (TryUnwrap(_certificate, wrappedDek, out var dek, out var failure))
        {
            return dek;
        }

        foreach (var previous in _previous)
        {
            if (TryUnwrap(previous, wrappedDek, out dek, out _))
            {
                return dek;
            }
        }

        throw failure!;
    }

    public bool IsWrappedByActiveKey(ReadOnlyMemory<byte> wrappedDek)
    {
        if (!TryUnwrap(_certificate, wrappedDek, out var dek, out _))
        {
            return false;
        }

        CryptographicOperations.ZeroMemory(dek);
        return true;
    }

    private static bool TryUnwrap(
        X509Certificate2 certificate,
        ReadOnlyMemory<byte> wrappedDek,
        out byte[] dek,
        out CryptographicException? failure)
    {
        using var rsa = certificate.GetRSAPrivateKey()
            ?? throw new CryptographicException(
                "The vault KEK certificate private key is unavailable.");
        try
        {
            dek = rsa.Decrypt(wrappedDek.Span, RSAEncryptionPadding.OaepSHA256);
            failure = null;
            return true;
        }
        catch (CryptographicException exception)
        {
            dek = [];
            failure = exception;
            return false;
        }
    }

    public void Dispose()
    {
        _certificate.Dispose();
        foreach (var previous in _previous)
        {
            previous.Dispose();
        }
    }
}
