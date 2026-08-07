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

internal sealed class MtlsClientCertificatePolicy(MtlsOptions options)
    : IMtlsClientCertificatePolicy
{
    public MtlsClientCertificateDecision Evaluate(
        HttpContext httpContext,
        string? clientId)
    {
        ArgumentNullException.ThrowIfNull(httpContext);
        if (!options.Enabled)
            return new(false, ReasonCode: "mtls_disabled");
        if (options.DeploymentMode == MtlsDeploymentMode.Unattested)
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
        if (!options.ClientCertificateThumbprints.TryGetValue(
                clientId,
                out var allowedThumbprints)
            || !allowedThumbprints
                .Select(NormalizeThumbprint)
                .Contains(thumbprint, StringComparer.Ordinal))
        {
            return new(false, thumbprint, "certificate_not_bound_to_client");
        }

        if (options.RequireValidCertificateChain)
        {
            using var chain = new X509Chain();
            chain.ChainPolicy.RevocationMode = X509RevocationMode.NoCheck;
            chain.ChainPolicy.VerificationFlags = X509VerificationFlags.NoFlag;
            if (!chain.Build(certificate))
            {
                return new(false, thumbprint, "certificate_chain_invalid");
            }
        }

        return new(true, thumbprint);
    }

    private static string NormalizeThumbprint(string value) =>
        value.Replace(":", string.Empty, StringComparison.Ordinal)
            .Replace(" ", string.Empty, StringComparison.Ordinal)
            .ToUpperInvariant();
}
