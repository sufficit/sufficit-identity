using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using OpenIddict.Abstractions;
using OpenIddict.Core;
using OpenIddict.EntityFrameworkCore.Models;
using Sufficit.Identity.Core.Data;
using Sufficit.Identity.Core.Entities;
using Sufficit.Identity.Core.Services;

namespace Sufficit.Identity.STS;

/// <summary>
/// Transitional OpenIddict adapter for Sufficit's provider-neutral client
/// credential registry. The legacy OpenIddict secret remains valid while
/// additional independently revocable secrets are resolved from our table.
/// </summary>
internal sealed class SufficitOpenIddictApplicationManager(
    IOpenIddictApplicationCache<OpenIddictEntityFrameworkCoreApplication> cache,
    ILogger<OpenIddictApplicationManager<OpenIddictEntityFrameworkCoreApplication>> logger,
    IOptionsMonitor<OpenIddictCoreOptions> options,
    IOpenIddictApplicationStore<OpenIddictEntityFrameworkCoreApplication> store,
    AppDbContext database,
    IClientCredentialSecretHasher secretHasher,
    MtlsOptions mtlsOptions)
    : OpenIddictApplicationManager<OpenIddictEntityFrameworkCoreApplication>(
        cache,
        logger,
        options,
        store)
{
    // This also bounds intentionally expensive PBKDF2 work if storage is
    // corrupted or modified outside the management service.
    internal const int MaximumActiveAdditionalSharedSecrets = 5;

    public override async ValueTask<bool> ValidateClientSecretAsync(
        OpenIddictEntityFrameworkCoreApplication application,
        string secret,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(application);
        ArgumentException.ThrowIfNullOrEmpty(secret);

        if (await base.ValidateClientSecretAsync(
                application,
                secret,
                cancellationToken))
        {
            return true;
        }

        if (!string.Equals(
                application.ClientType,
                OpenIddict.Abstractions.OpenIddictConstants.ClientTypes.Confidential,
                StringComparison.Ordinal)
            || string.IsNullOrWhiteSpace(application.ClientId))
        {
            return false;
        }

        var now = DateTime.UtcNow;
        var candidates = await database.OAuthClientCredentials
            .AsNoTracking()
            .Where(credential =>
                credential.ClientId == application.ClientId
                && credential.Kind == OAuthClientCredentialKinds.SharedSecret
                && credential.RevokedAtUtc == null
                && (credential.NotBeforeUtc == null || credential.NotBeforeUtc <= now)
                && (credential.ExpiresAtUtc == null || credential.ExpiresAtUtc > now))
            .OrderByDescending(credential => credential.CreatedAtUtc)
            .Take(MaximumActiveAdditionalSharedSecrets)
            .Select(credential => credential.SecretHash)
            .ToArrayAsync(cancellationToken);

        foreach (var hash in candidates)
        {
            if (secretHasher.Verify(hash, secret))
            {
                return true;
            }
        }

        return false;
    }

    public override async ValueTask<bool>
        ValidateSelfSignedTlsClientCertificateAsync(
            OpenIddictEntityFrameworkCoreApplication application,
            X509Certificate2 certificate,
            X509ChainPolicy policy,
            CancellationToken cancellationToken = default)
    {
        if (await base.ValidateSelfSignedTlsClientCertificateAsync(
                application,
                certificate,
                policy,
                cancellationToken))
        {
            return true;
        }

        // Rolling compatibility for the previous configuration-only pin
        // registry. New certificates are persisted in the application JWKS.
        if (string.IsNullOrWhiteSpace(application.ClientId)
            || !mtlsOptions.ClientCertificateThumbprints.TryGetValue(
                application.ClientId,
                out var configured)
            || !configured.Select(NormalizeThumbprint).Contains(
                NormalizeThumbprint(certificate.GetCertHashString(
                    HashAlgorithmName.SHA256)),
                StringComparer.Ordinal))
        {
            return false;
        }

        var compatibilityPolicy = policy.Clone();
        compatibilityPolicy.CustomTrustStore.Add(certificate);
        return await base.ValidateSelfSignedTlsClientCertificateAsync(
            application,
            certificate,
            compatibilityPolicy,
            cancellationToken);
    }

    private static string NormalizeThumbprint(string value) =>
        value.Replace(":", string.Empty, StringComparison.Ordinal)
            .Replace(" ", string.Empty, StringComparison.Ordinal)
            .ToUpperInvariant();
}
