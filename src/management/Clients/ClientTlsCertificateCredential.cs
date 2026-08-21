using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using Microsoft.IdentityModel.Tokens;
using OpenIddict.Abstractions;
using Sufficit.Identity.Management.Authorization;

namespace Sufficit.Identity.Management.Clients;

internal static class ClientTlsCertificateCredential
{
    public const int MaximumCertificates = 10;
    private const string ClientAuthenticationExtendedKeyUsage =
        "1.3.6.1.5.5.7.3.2";

    public static JsonWebKey Create(
        string certificatePem,
        string? keyId,
        string authenticationMethod)
    {
        if (string.IsNullOrWhiteSpace(certificatePem))
        {
            throw new ManagementValidationException(
                "mtls_certificate_required",
                "Informe o certificado público em formato PEM.",
                "certificatePem");
        }
        if (certificatePem.Length > 64 * 1024)
        {
            throw new ManagementValidationException(
                "mtls_certificate_too_large",
                "O certificado público não pode ultrapassar 64 KiB.",
                "certificatePem");
        }
        if (certificatePem.Contains("PRIVATE KEY-----", StringComparison.Ordinal))
        {
            throw new ManagementValidationException(
                "mtls_private_key_forbidden",
                "Envie somente o certificado público. A chave privada deve permanecer no cliente.",
                "certificatePem");
        }

        using var certificate = ParseCertificate(certificatePem);
        if (certificate.HasPrivateKey)
        {
            throw new ManagementValidationException(
                "mtls_private_key_forbidden",
                "Envie somente o certificado público. A chave privada deve permanecer no cliente.",
                "certificatePem");
        }

        ValidateCertificate(certificate, authenticationMethod);
        var normalizedKeyId = ValidateKeyId(keyId, certificate);
        var key = JsonWebKeyConverter.ConvertFromX509SecurityKey(
            new X509SecurityKey(certificate));
        key.Kid = normalizedKeyId;
        key.Use = JsonWebKeyUseNames.Sig;
        return key;
    }

    public static IReadOnlyList<ManagementClientTlsCertificateSummary> Read(
        string? jsonWebKeySet,
        DateTimeOffset now)
    {
        if (string.IsNullOrWhiteSpace(jsonWebKeySet))
        {
            return [];
        }

        var result = new List<ManagementClientTlsCertificateSummary>();
        foreach (var key in new JsonWebKeySet(jsonWebKeySet).Keys)
        {
            if (!TryReadCertificate(key, out var certificate))
            {
                continue;
            }

            using (certificate)
            {
                var isCertificateAuthority = IsCertificateAuthority(certificate);
                var status = certificate.NotBefore.ToUniversalTime() > now.UtcDateTime
                    ? "scheduled"
                    : certificate.NotAfter.ToUniversalTime() <= now.UtcDateTime
                        ? "expired"
                        : "active";
                result.Add(new ManagementClientTlsCertificateSummary(
                    string.IsNullOrWhiteSpace(key.Kid)
                        ? DefaultKeyId(certificate)
                        : key.Kid,
                    isCertificateAuthority
                        ? OpenIddictConstants.ClientAuthenticationMethods.TlsClientAuth
                        : OpenIddictConstants.ClientAuthenticationMethods.SelfSignedTlsClientAuth,
                    certificate.Subject,
                    certificate.Issuer,
                    certificate.GetCertHashString(HashAlgorithmName.SHA256),
                    new DateTimeOffset(certificate.NotBefore.ToUniversalTime()),
                    new DateTimeOffset(certificate.NotAfter.ToUniversalTime()),
                    status,
                    isCertificateAuthority));
            }
        }

        return result
            .OrderBy(item => item.ExpiresAtUtc)
            .ThenBy(item => item.KeyId, StringComparer.Ordinal)
            .ToArray();
    }

    public static JsonWebKeySet? ExtractPrivateKeyJwtKeys(string? jsonWebKeySet)
    {
        if (string.IsNullOrWhiteSpace(jsonWebKeySet))
        {
            return null;
        }

        var source = new JsonWebKeySet(jsonWebKeySet);
        var result = new JsonWebKeySet();
        foreach (var key in source.Keys.Where(key => !HasCertificate(key)))
        {
            result.Keys.Add(key);
        }

        return result.Keys.Count == 0 ? null : result;
    }

    public static JsonWebKeySet? MergePrivateKeyJwtKeys(
        JsonWebKeySet? privateKeys,
        string? existingJsonWebKeySet)
    {
        var result = new JsonWebKeySet();
        if (!string.IsNullOrWhiteSpace(existingJsonWebKeySet))
        {
            foreach (var key in new JsonWebKeySet(existingJsonWebKeySet).Keys
                .Where(HasCertificate))
            {
                result.Keys.Add(key);
            }
        }
        if (privateKeys is not null)
        {
            foreach (var key in privateKeys.Keys)
            {
                result.Keys.Add(key);
            }
        }

        return result.Keys.Count == 0 ? null : result;
    }

    public static JsonWebKeySet AddCertificate(
        string? existingJsonWebKeySet,
        JsonWebKey certificate)
    {
        var result = string.IsNullOrWhiteSpace(existingJsonWebKeySet)
            ? new JsonWebKeySet()
            : new JsonWebKeySet(existingJsonWebKeySet);
        var certificates = result.Keys.Where(HasCertificate).ToArray();
        if (certificates.Length >= MaximumCertificates)
        {
            throw new ManagementConflictException(
                "mtls_certificate_limit_reached",
                $"Cada aplicação pode manter até {MaximumCertificates} certificados mTLS durante a rotação.");
        }
        if (result.Keys.Any(key => string.Equals(
                key.Kid,
                certificate.Kid,
                StringComparison.Ordinal)))
        {
            throw new ManagementConflictException(
                "mtls_certificate_kid_duplicate",
                "Já existe uma chave pública com esse identificador (kid).");
        }

        var thumbprint = CertificateThumbprint(certificate);
        if (thumbprint is not null && certificates.Any(candidate =>
                string.Equals(
                    CertificateThumbprint(candidate),
                    thumbprint,
                    StringComparison.Ordinal)))
        {
            throw new ManagementConflictException(
                "mtls_certificate_duplicate",
                "Este certificado já está registrado para a aplicação.");
        }

        result.Keys.Add(certificate);
        return result;
    }

    public static JsonWebKeySet? RemoveCertificate(
        string? existingJsonWebKeySet,
        string keyId)
    {
        if (string.IsNullOrWhiteSpace(existingJsonWebKeySet))
        {
            throw new ManagementNotFoundException(
                "mtls_certificate_not_found",
                "O certificado mTLS não foi encontrado.");
        }

        var source = new JsonWebKeySet(existingJsonWebKeySet);
        var result = new JsonWebKeySet();
        var removed = false;
        foreach (var key in source.Keys)
        {
            if (!removed && HasCertificate(key) && string.Equals(
                    key.Kid,
                    keyId,
                    StringComparison.Ordinal))
            {
                removed = true;
                continue;
            }

            result.Keys.Add(key);
        }

        if (!removed)
        {
            throw new ManagementNotFoundException(
                "mtls_certificate_not_found",
                "O certificado mTLS não foi encontrado.");
        }

        return result.Keys.Count == 0 ? null : result;
    }

    private static X509Certificate2 ParseCertificate(string certificatePem)
    {
        try
        {
            return X509Certificate2.CreateFromPem(certificatePem);
        }
        catch (Exception exception) when (
            exception is CryptographicException or ArgumentException)
        {
            throw new ManagementValidationException(
                "mtls_certificate_invalid",
                $"O certificado PEM não pôde ser interpretado: {exception.Message}",
                "certificatePem");
        }
    }

    private static void ValidateCertificate(
        X509Certificate2 certificate,
        string authenticationMethod)
    {
        if (authenticationMethod ==
            OpenIddictConstants.ClientAuthenticationMethods.SelfSignedTlsClientAuth)
        {
            if (!certificate.SubjectName.RawData.AsSpan()
                .SequenceEqual(certificate.IssuerName.RawData))
            {
                throw new ManagementValidationException(
                    "mtls_certificate_not_self_signed",
                    "self_signed_tls_client_auth exige um certificado autoassinado.",
                    "certificatePem");
            }
            if (!HasKeyUsage(certificate, X509KeyUsageFlags.DigitalSignature))
            {
                throw new ManagementValidationException(
                    "mtls_certificate_key_usage_invalid",
                    "O certificado deve declarar o uso digitalSignature.",
                    "certificatePem");
            }
            if (!HasExtendedKeyUsage(
                    certificate,
                    ClientAuthenticationExtendedKeyUsage))
            {
                throw new ManagementValidationException(
                    "mtls_certificate_extended_key_usage_invalid",
                    "O certificado deve declarar o uso estendido clientAuth.",
                    "certificatePem");
            }

            using var chain = new X509Chain();
            chain.ChainPolicy.TrustMode = X509ChainTrustMode.CustomRootTrust;
            chain.ChainPolicy.CustomTrustStore.Add(certificate);
            chain.ChainPolicy.RevocationMode = X509RevocationMode.NoCheck;
            if (!chain.Build(certificate) || chain.ChainElements.Count != 1)
            {
                throw new ManagementValidationException(
                    "mtls_certificate_signature_invalid",
                    "O certificado informado é autoemitido, mas sua assinatura não é válida como certificado autoassinado.",
                    "certificatePem");
            }
            return;
        }

        if (authenticationMethod ==
            OpenIddictConstants.ClientAuthenticationMethods.TlsClientAuth)
        {
            if (!IsCertificateAuthority(certificate)
                || !HasKeyUsage(certificate, X509KeyUsageFlags.KeyCertSign)
                || certificate.SubjectName.RawData.AsSpan()
                    .SequenceEqual(certificate.IssuerName.RawData))
            {
                throw new ManagementValidationException(
                    "mtls_pki_certificate_invalid",
                    "Para tls_client_auth, envie uma CA subordinada não autoemitida com basicConstraints CA e keyCertSign.",
                    "certificatePem");
            }
            return;
        }

        throw new ManagementValidationException(
            "mtls_authentication_method_invalid",
            "Use self_signed_tls_client_auth ou tls_client_auth.",
            "authenticationMethod");
    }

    private static string ValidateKeyId(
        string? keyId,
        X509Certificate2 certificate)
    {
        var value = string.IsNullOrWhiteSpace(keyId)
            ? DefaultKeyId(certificate)
            : keyId.Trim();
        if (value.Length is < 1 or > 100
            || value.Any(character =>
                !(char.IsAsciiLetterOrDigit(character)
                    || character is '-' or '_' or '.' or ':')))
        {
            throw new ManagementValidationException(
                "mtls_certificate_kid_invalid",
                "O identificador (kid) deve ter até 100 caracteres e usar letras, números, ponto, hífen, sublinhado ou dois-pontos.",
                "keyId");
        }

        return value;
    }

    private static string DefaultKeyId(X509Certificate2 certificate) =>
        "mtls-" + Base64UrlEncoder.Encode(
            SHA256.HashData(certificate.RawData))[..22];

    private static bool HasCertificate(JsonWebKey key) =>
        key.X5c is { Count: > 0 };

    private static string? CertificateThumbprint(JsonWebKey key)
    {
        if (!TryReadCertificate(key, out var certificate))
        {
            return null;
        }

        using (certificate)
        {
            return certificate.GetCertHashString(HashAlgorithmName.SHA256);
        }
    }

    private static bool TryReadCertificate(
        JsonWebKey key,
        out X509Certificate2 certificate)
    {
        certificate = null!;
        if (key.X5c is not { Count: > 0 })
        {
            return false;
        }

        try
        {
            certificate = X509CertificateLoader.LoadCertificate(
                Convert.FromBase64String(key.X5c[0]));
            return true;
        }
        catch (Exception exception) when (
            exception is FormatException or CryptographicException)
        {
            return false;
        }
    }

    private static bool IsCertificateAuthority(X509Certificate2 certificate) =>
        certificate.Extensions
            .OfType<X509BasicConstraintsExtension>()
            .Any(extension => extension.CertificateAuthority);

    private static bool HasKeyUsage(
        X509Certificate2 certificate,
        X509KeyUsageFlags usage) =>
        certificate.Extensions
            .OfType<X509KeyUsageExtension>()
            .Any(extension => extension.KeyUsages.HasFlag(usage));

    private static bool HasExtendedKeyUsage(
        X509Certificate2 certificate,
        string oid) =>
        certificate.Extensions
            .OfType<X509EnhancedKeyUsageExtension>()
            .Any(extension => extension.EnhancedKeyUsages
                .Cast<Oid>()
                .Any(candidate => string.Equals(
                    candidate.Value,
                    oid,
                    StringComparison.Ordinal)));
}
