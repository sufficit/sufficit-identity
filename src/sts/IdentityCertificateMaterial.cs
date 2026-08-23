using System.Security.Cryptography.X509Certificates;
using Microsoft.IdentityModel.Tokens;

namespace Sufficit.Identity.STS;

/// <summary>
/// The signing and encryption certificates a deployment presents, plus the
/// rules that decide whether they may be used at all.
/// </summary>
/// <remarks>
/// Extracted from <c>ServiceCollectionExtensions</c>, where these rules were
/// buried among two thousand lines of DI registration. This is the material
/// every token is signed with, and it carries the fail-closed guards that
/// separate a real deployment from a misconfigured one: outside Development,
/// a missing certificate is a startup failure rather than a silent fall back
/// to a throwaway key that changes on every restart.
/// <para>
/// Passwords arrive already resolved. The loader has no business knowing
/// where secrets come from, and keeping <c>ISecretStore</c> out of it makes
/// the whole type a pure function of its inputs.
/// </para>
/// </remarks>
internal static class IdentityCertificateMaterial
{
    /// <summary>
    /// Loads and validates both certificate sets, enforcing the production
    /// requirements: certificates must exist outside Development, and — when
    /// requested — signing and encryption must not be the same certificate.
    /// </summary>
    internal static CertificateMaterial Load(
        CertificatesOptions options,
        bool isDevelopmentEnvironment,
        string? signingPassword,
        string? encryptionPassword)
    {
        var signing = LoadCertificateSet(
            options.SigningPath,
            options.SigningPaths,
            signingPassword,
            "signing",
            options);
        var encryption = LoadCertificateSet(
            options.EncryptionPath,
            options.EncryptionPaths,
            encryptionPassword,
            "encryption",
            options);

        if (!isDevelopmentEnvironment
            && (signing.Count == 0 || encryption.Count == 0))
        {
            throw new InvalidOperationException(
                "Production deployments require persistent signing and encryption certificates.");
        }

        // Reusing one certificate for both purposes means a single key
        // compromise costs both confidentiality and authenticity at once.
        if (options.RequirePurposeSeparation
            && signing.Count > 0
            && encryption.Count > 0
            && string.Equals(
                signing[0].Thumbprint,
                encryption[0].Thumbprint,
                StringComparison.OrdinalIgnoreCase))
        {
            throw new InvalidOperationException(
                "Certificate purpose separation requires different active signing and encryption certificates.");
        }

        return new CertificateMaterial(signing, encryption);
    }

    /// <summary>
    /// Resolves the signing credentials used by auxiliary protocol JWTs
    /// (logout_token, JARM, SSF/CAEP, CIBA). Reuses the STS signing
    /// certificate when configured; otherwise falls back to one ephemeral
    /// ECDSA P-256 key for Development/tests. The caller also registers that
    /// development key with OpenIddict so it is published by the normal JWKS
    /// endpoint — without that, those JWTs would verify in-process only.
    /// </summary>
    internal static SigningCredentials ResolveProtocolSigningCredentials(
        X509Certificate2? certificate,
        bool isDevelopmentEnvironment)
    {
        if (certificate is not null)
        {
            var algorithm = certificate.GetECDsaPrivateKey() is not null
                ? SecurityAlgorithms.EcdsaSha256
                : certificate.GetRSAPrivateKey() is not null
                    ? SecurityAlgorithms.RsaSha256
                    : throw new InvalidOperationException(
                        "The configured signing certificate must contain an RSA or ECDSA private key.");
            return new SigningCredentials(
                new X509SecurityKey(certificate),
                algorithm);
        }

        if (isDevelopmentEnvironment)
        {
            // Ephemeral ECDSA P-256 key — fine for tests/dev where the issuer
            // and validator are the same process. Never used in production.
            var ecdsa = System.Security.Cryptography.ECDsa.Create(
                System.Security.Cryptography.ECCurve.NamedCurves.nistP256);
            return new SigningCredentials(
                new ECDsaSecurityKey(ecdsa)
                {
                    KeyId = Guid.NewGuid().ToString("N"),
                },
                SecurityAlgorithms.EcdsaSha256);
        }

        throw new InvalidOperationException(
            "No signing certificate is configured for protocol JWTs. " +
            "Production deployments require Sufficit:Identity:Certificates:SigningPath " +
            "(the logout_token is signed with the same key as access tokens).");
    }

    /// <summary>
    /// Loads a primary certificate plus any rotation-overlap certificates,
    /// de-duplicating by thumbprint so the same file listed twice does not
    /// publish a duplicate key.
    /// </summary>
    private static IReadOnlyList<X509Certificate2> LoadCertificateSet(
        string? primaryPath,
        IEnumerable<string>? overlapPaths,
        string? password,
        string purpose,
        CertificatesOptions options)
    {
        var paths = new[] { primaryPath }
            .Concat(overlapPaths ?? [])
            .Where(path => !string.IsNullOrWhiteSpace(path))
            .Select(path => path!.Trim())
            .Distinct(StringComparer.Ordinal)
            .ToArray();
        var certificates = new List<X509Certificate2>(paths.Length);
        var thumbprints = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        foreach (var path in paths)
        {
            var certificate = X509CertificateLoader.LoadPkcs12FromFile(
                path,
                password);
            ValidateCertificate(certificate, purpose, options);
            if (!thumbprints.Add(certificate.Thumbprint))
            {
                certificate.Dispose();
                continue;
            }

            certificates.Add(certificate);
        }

        return certificates;
    }

    private static void ValidateCertificate(
        X509Certificate2? certificate,
        string purpose,
        CertificatesOptions options)
    {
        if (certificate is null)
        {
            return;
        }

        if (!certificate.HasPrivateKey)
        {
            throw new InvalidOperationException(
                $"The configured {purpose} certificate does not contain a private key.");
        }

        var now = DateTimeOffset.UtcNow;
        if (certificate.NotBefore.ToUniversalTime() > now.UtcDateTime
            || certificate.NotAfter.ToUniversalTime() <= now.UtcDateTime)
        {
            throw new InvalidOperationException(
                $"The configured {purpose} certificate is not currently valid.");
        }

        // Expiry is the failure mode that takes an STS down wholesale, so it
        // is surfaced before it happens rather than at the moment it bites.
        var minimumLifetime = TimeSpan.FromDays(
            Math.Clamp(options.MinimumRemainingLifetimeDays, 1, 365));
        if (certificate.NotAfter.ToUniversalTime() - now.UtcDateTime < minimumLifetime)
        {
            var message =
                $"The configured {purpose} certificate expires at {certificate.NotAfter:u}, inside the {minimumLifetime.TotalDays:0}-day rotation window.";
            if (options.FailOnExpiringCertificate)
            {
                throw new InvalidOperationException(message);
            }

            Console.Error.WriteLine("[WARNING] " + message);
        }
    }
}

/// <summary>
/// The certificate sets in use. The first entry of each is the active one;
/// any others are rotation-overlap certificates kept verifiable while
/// consumers migrate.
/// </summary>
internal sealed record CertificateMaterial(
    IReadOnlyList<X509Certificate2> Signing,
    IReadOnlyList<X509Certificate2> Encryption)
{
    public X509Certificate2? PrimarySigning => Signing.FirstOrDefault();
}
