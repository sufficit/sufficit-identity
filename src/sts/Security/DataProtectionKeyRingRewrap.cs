using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Xml.Linq;
using Microsoft.AspNetCore.DataProtection.XmlEncryption;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging;
using Sufficit.Identity.Core.Data;

namespace Sufficit.Identity.STS.Security;

/// <summary>Outcome of <see cref="DataProtectionKeyRingRewrap.RewrapAsync"/>. Counts and row ids only.</summary>
public sealed record DataProtectionKeyRingRewrapResult(int Rewrapped, int AlreadyActive, IReadOnlyList<int> Failed);

/// <summary>
/// Re-encrypts the Data Protection key ring under the active vault KEK
/// certificate (plan C1). Data Protection never re-encrypts a stored key: a
/// key written under a retiring certificate stays under it, so without this
/// step the old certificate could never leave
/// <c>Sufficit:Vault:PreviousCertificatePaths</c>.
/// </summary>
public static class DataProtectionKeyRingRewrap
{
    private const string EncryptedSecretElement = "encryptedSecret";
    private const string DecryptorTypeAttribute = "decryptorType";

    /// <param name="services">The application's root provider: its Data
    /// Protection options carry the decrypt-only certificates.</param>
    public static async Task<DataProtectionKeyRingRewrapResult> RewrapAsync(
        AppDbContext database,
        IServiceProvider services,
        X509Certificate2 activeCertificate,
        ILoggerFactory loggerFactory,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(database);
        ArgumentNullException.ThrowIfNull(activeCertificate);
        var decryptor = new EncryptedXmlDecryptor(services);
        var encryptor = new CertificateXmlEncryptor(activeCertificate, loggerFactory);
        var active = Convert.ToBase64String(activeCertificate.RawData);

        int rewrapped = 0, alreadyActive = 0;
        var failed = new List<int>();
        var rows = await database.DataProtectionKeys.ToListAsync(cancellationToken);
        foreach (var row in rows)
        {
            if (string.IsNullOrWhiteSpace(row.Xml))
            {
                continue;
            }

            var key = XElement.Parse(row.Xml);
            var changed = false;
            foreach (var secret in key.Descendants()
                         .Where(element => element.Name.LocalName == EncryptedSecretElement)
                         .ToList())
            {
                var encrypted = secret.Elements().FirstOrDefault();
                if (encrypted is null)
                {
                    continue;
                }

                if (IsEncryptedFor(encrypted, active))
                {
                    alreadyActive++;
                    continue;
                }

                XElement plaintext;
                try
                {
                    plaintext = decryptor.Decrypt(encrypted);
                }
                catch (CryptographicException)
                {
                    failed.Add(row.Id);
                    continue;
                }

                var info = encryptor.Encrypt(plaintext);
                secret.SetAttributeValue(DecryptorTypeAttribute, info.DecryptorType.AssemblyQualifiedName);
                secret.ReplaceNodes(info.EncryptedElement);
                changed = true;
                rewrapped++;
            }

            if (changed)
            {
                row.Xml = key.ToString(SaveOptions.DisableFormatting);
            }
        }

        await database.SaveChangesAsync(cancellationToken);
        return new DataProtectionKeyRingRewrapResult(rewrapped, alreadyActive, failed);
    }

    // EncryptedXml names the recipient certificate in KeyInfo/X509Data.
    private static bool IsEncryptedFor(XElement encrypted, string certificateBase64) =>
        encrypted.Descendants()
            .Where(element => element.Name.LocalName == "X509Certificate")
            .Any(element => string.Equals(
                string.Concat(element.Value.Where(character => !char.IsWhiteSpace(character))),
                certificateBase64,
                StringComparison.Ordinal));
}
