using Microsoft.AspNetCore.DataProtection;

namespace Sufficit.Identity.Vault;

/// <summary>
/// Default <c>KEK</c> (Key Encryption Key) source: ASP.NET Core Data
/// Protection. Wraps/unwraps vault DEKs via <see cref="IDataProtector"/> with
/// a configured purpose string. Zero new dependencies — Data Protection is
/// already used by the STS (key ring persisted to the DB, optionally X.509-
/// protected). This inherits all that hardening for free.
/// </summary>
internal sealed class DataProtectionKeySource
{
    private readonly IDataProtector _protector;

    public DataProtectionKeySource(
        IDataProtectionProvider dataProtectionProvider,
        VaultOptions options)
    {
        _protector = dataProtectionProvider.CreateProtector(options.DataProtectionPurpose);
    }

    /// <summary>Wraps (encrypts) a DEK under the KEK.</summary>
    public byte[] Wrap(ReadOnlyMemory<byte> dek) => _protector.Protect(dek.ToArray());

    /// <summary>Unwraps (decrypts) a wrapped DEK.</summary>
    public byte[] Unwrap(ReadOnlyMemory<byte> wrappedDek) => _protector.Unprotect(wrappedDek.ToArray());
}
