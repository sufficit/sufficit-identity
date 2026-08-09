using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using Microsoft.AspNetCore.Http;

namespace Sufficit.Identity.STS.Mtls;

public sealed record MtlsClientCertificateDecision(
    bool Allowed,
    string? Thumbprint = null,
    string? ReasonCode = null);

public interface IMtlsClientCertificatePolicy
{
    MtlsClientCertificateDecision Evaluate(
        HttpContext httpContext,
        string? clientId);
}

internal sealed record MtlsCertificateChainResult(
    bool IsValid,
    X509ChainStatusFlags StatusFlags);

internal interface IMtlsCertificateChainValidator
{
    MtlsCertificateChainResult Validate(
        X509Certificate2 certificate,
        MtlsCertificateRevocationMode revocationMode,
        TimeSpan timeout);
}

internal sealed class SystemMtlsCertificateChainValidator
    : IMtlsCertificateChainValidator
{
    public MtlsCertificateChainResult Validate(
        X509Certificate2 certificate,
        MtlsCertificateRevocationMode revocationMode,
        TimeSpan timeout)
    {
        using var chain = new X509Chain();
        chain.ChainPolicy.RevocationMode = ToPlatformMode(revocationMode);
        chain.ChainPolicy.RevocationFlag = X509RevocationFlag.EntireChain;
        chain.ChainPolicy.UrlRetrievalTimeout = timeout;
        chain.ChainPolicy.DisableCertificateDownloads =
            revocationMode == MtlsCertificateRevocationMode.Offline;
        chain.ChainPolicy.VerificationFlags = X509VerificationFlags.NoFlag;
        var valid = chain.Build(certificate);
        var flags = chain.ChainStatus.Aggregate(
            X509ChainStatusFlags.NoError,
            (current, status) => current | status.Status);
        return new(valid, flags);
    }

    internal static X509RevocationMode ToPlatformMode(
        MtlsCertificateRevocationMode mode) => mode switch
    {
        MtlsCertificateRevocationMode.NoCheck => X509RevocationMode.NoCheck,
        MtlsCertificateRevocationMode.Online => X509RevocationMode.Online,
        MtlsCertificateRevocationMode.Offline => X509RevocationMode.Offline,
        _ => throw new ArgumentOutOfRangeException(nameof(mode)),
    };
}

internal sealed class MtlsClientCertificatePolicy : IMtlsClientCertificatePolicy
{
    private const X509ChainStatusFlags RevocationUnavailableFlags =
        X509ChainStatusFlags.RevocationStatusUnknown
        | X509ChainStatusFlags.OfflineRevocation;
    private readonly MtlsOptions _options;
    private readonly IMtlsCertificateChainValidator _chainValidator;

    public MtlsClientCertificatePolicy(
        MtlsOptions options,
        IMtlsCertificateChainValidator chainValidator)
    {
        _options = options;
        _chainValidator = chainValidator;
    }

    internal MtlsClientCertificatePolicy(MtlsOptions options)
        : this(options, new SystemMtlsCertificateChainValidator())
    {
    }

    public MtlsClientCertificateDecision Evaluate(
        HttpContext httpContext,
        string? clientId)
    {
        ArgumentNullException.ThrowIfNull(httpContext);
        if (!_options.Enabled)
            return new(false, ReasonCode: "mtls_disabled");
        if (_options.DeploymentMode == MtlsDeploymentMode.Unattested)
            return new(false, ReasonCode: "deployment_unattested");
        if (string.IsNullOrWhiteSpace(clientId))
            return new(false, ReasonCode: "client_id_missing");

        var certificate = httpContext.Connection.ClientCertificate;
        if (certificate is null)
            return new(false, ReasonCode: "certificate_missing");
        var now = DateTimeOffset.UtcNow;
        if (certificate.NotBefore.ToUniversalTime() > now.UtcDateTime
            || certificate.NotAfter.ToUniversalTime() <= now.UtcDateTime)
        {
            return new(false, ReasonCode: "certificate_not_current");
        }

        var thumbprint = NormalizeThumbprint(
            certificate.GetCertHashString(HashAlgorithmName.SHA256));
        if (!_options.ClientCertificateThumbprints.TryGetValue(
                clientId,
                out var allowedThumbprints)
            || !allowedThumbprints
                .Select(NormalizeThumbprint)
                .Contains(thumbprint, StringComparer.Ordinal))
        {
            return new(false, thumbprint, "certificate_not_bound_to_client");
        }

        if (_options.RequireValidCertificateChain)
        {
            var chain = _chainValidator.Validate(
                certificate,
                _options.RevocationMode,
                TimeSpan.FromSeconds(_options.RevocationTimeoutSeconds));
            if (!chain.IsValid)
            {
                if ((chain.StatusFlags & X509ChainStatusFlags.Revoked) != 0)
                {
                    return new(false, thumbprint, "certificate_revoked");
                }

                if (IsRevocationUnavailableOnly(chain.StatusFlags))
                {
                    if (_options.RevocationFailureMode ==
                        MtlsRevocationFailureMode.AllowWhenUnavailable)
                    {
                        return new(
                            true,
                            thumbprint,
                            "certificate_revocation_unavailable_allowed");
                    }
                    return new(
                        false,
                        thumbprint,
                        "certificate_revocation_unavailable");
                }

                return new(false, thumbprint, "certificate_chain_invalid");
            }
        }

        return new(true, thumbprint);
    }

    private static string NormalizeThumbprint(string value) =>
        value.Replace(":", string.Empty, StringComparison.Ordinal)
            .Replace(" ", string.Empty, StringComparison.Ordinal)
            .ToUpperInvariant();

    private static bool IsRevocationUnavailableOnly(
        X509ChainStatusFlags flags) =>
        flags != X509ChainStatusFlags.NoError
        && (flags & ~RevocationUnavailableFlags) == X509ChainStatusFlags.NoError;
}
