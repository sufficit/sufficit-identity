using System.Security.Cryptography;
using Microsoft.IdentityModel.Tokens;
using Microsoft.AspNetCore.WebUtilities;
using OpenIddict.EntityFrameworkCore.Models;
using Sufficit.Identity.Core.Data;
using Sufficit.Identity.Core.Entities;
using Sufficit.Identity.Management.Authorization;

namespace Sufficit.Identity.Management.Clients;

/// <summary>
/// Rules for the credentials a client authenticates with: what an acceptable
/// shared secret looks like, the labels and validity windows around it, and
/// how the resulting authentication methods are reported back.
/// </summary>
/// <remarks>
/// Extracted from <c>ClientManagementService</c>. Deciding what counts as an
/// acceptable client secret is a security question rather than bookkeeping,
/// so it is kept apart from the CRUD that surrounded it. Behavior is
/// unchanged; reason codes and messages are part of the API contract and are
/// reproduced exactly.
/// </remarks>
internal static class ClientCredentialPolicy
{
    // A client secret is machine-generated and machine-stored, so there is no
    // usability argument for tolerating a short one.
    internal const int MinimumClientSecretLength = 32;
    internal const int MaximumClientSecretLength = 512;

    // Two years: long enough to avoid churn, short enough that a
    // forgotten credential does not outlive the system it guards.
    internal const int MaximumClientCredentialLifetimeDays = 730;

    /// <summary>Entropy of a generated client secret: 32 bytes = 256 bits.</summary>
    internal const int GeneratedClientSecretBytes = 32;

    /// <summary>
    /// Ceiling on additional live shared secrets per client. Overlap exists
    /// to make rotation possible, not to let credentials accumulate
    /// indefinitely — each extra one is another way in.
    /// </summary>
    internal const int MaximumActiveAdditionalSharedSecrets = 5;

    /// <summary>Fresh optimistic-concurrency stamp for a client row.</summary>
    internal static string NewConcurrencyToken() =>
        Guid.NewGuid().ToString("N");

    internal static void EnsureExpectedClientVersion(
        string? expectedVersion,
        OpenIddictEntityFrameworkCoreApplication application)
    {
        if (string.IsNullOrWhiteSpace(expectedVersion))
        {
            throw new ManagementValidationException(
                "client_version_required",
                "Reload the application before adding a credential.",
                "expectedClientVersion");
        }
        if (!string.Equals(
                expectedVersion,
                application.ConcurrencyToken,
                StringComparison.Ordinal))
        {
            throw new ManagementConflictException(
                "client_changed",
                "The application was changed by another operation. Reload the data.");
        }
    }

    internal static IReadOnlyList<string> GetAuthenticationMethods(
        bool hasActiveSharedSecret,
        string? publicJwksJson,
        IReadOnlyList<ManagementClientTlsCertificateSummary>? tlsCertificates = null)
    {
        var methods = new List<string>(3);
        if (hasActiveSharedSecret)
        {
            methods.Add("client_secret_basic");
            methods.Add("client_secret_post");
        }
        if (HasPublicSigningKeys(publicJwksJson))
        {
            methods.Add("private_key_jwt");
        }
        foreach (var method in (tlsCertificates ?? [])
            .Where(certificate => certificate.Status == "active")
            .Select(certificate => certificate.AuthenticationMethod)
            .Distinct(StringComparer.Ordinal))
        {
            methods.Add(method);
        }

        return methods;
    }

    internal static bool HasPublicSigningKeys(string? publicJwksJson)
    {
        if (string.IsNullOrWhiteSpace(publicJwksJson))
        {
            return false;
        }

        try
        {
            var set = new JsonWebKeySet(publicJwksJson);
            return set.Keys.Any(key =>
                key.X5c is not { Count: > 0 }
                &&
                key.Kty is JsonWebAlgorithmsKeyTypes.RSA
                    or JsonWebAlgorithmsKeyTypes.EllipticCurve
                && key.Use is null or JsonWebKeyUseNames.Sig);
        }
        catch (ArgumentException)
        {
            return false;
        }
    }

    internal static string GetCredentialStatus(
        OAuthClientCredential credential,
        DateTime now)
    {
        if (credential.RevokedAtUtc is not null)
        {
            return "revoked";
        }
        if (credential.ExpiresAtUtc is { } expiresAt && expiresAt <= now)
        {
            return "expired";
        }
        if (credential.NotBeforeUtc is { } notBefore && notBefore > now)
        {
            return "scheduled";
        }

        return "active";
    }

    internal static DateTimeOffset? ToDateTimeOffset(DateTime? value) =>
        value is null
            ? null
            : new DateTimeOffset(
                DateTime.SpecifyKind(value.Value, DateTimeKind.Utc));

    internal static string ValidateCredentialLabel(string? value)
    {
        var label = value?.Trim() ?? string.Empty;
        if (label.Length is < 1 or > IdentityDatabaseSchema.OAuthClientCredentialLabelLength)
        {
            throw new ManagementValidationException(
                "client_credential_label_invalid",
                $"The name must be between 1 and {IdentityDatabaseSchema.OAuthClientCredentialLabelLength} characters.",
                "label");
        }
        if (label.Any(char.IsControl))
        {
            throw new ManagementValidationException(
                "client_credential_label_invalid",
                "The credential name cannot contain control characters.",
                "label");
        }

        return label;
    }

    internal static void ValidateCredentialLifetime(
        DateTime now,
        DateTime? notBeforeUtc,
        DateTime? expiresAtUtc)
    {
        if (expiresAtUtc is { } expiresAt && expiresAt <= now)
        {
            throw new ManagementValidationException(
                "client_credential_expiration_invalid",
                "The expiration must be in the future.",
                "expiresAtUtc");
        }
        if (expiresAtUtc is { } boundedExpiry
            && boundedExpiry > now.AddDays(MaximumClientCredentialLifetimeDays))
        {
            throw new ManagementValidationException(
                "client_credential_expiration_too_distant",
                $"The expiration cannot exceed {MaximumClientCredentialLifetimeDays} days.",
                "expiresAtUtc");
        }
        if (notBeforeUtc is { } notBefore
            && expiresAtUtc is { } expiry
            && notBefore >= expiry)
        {
            throw new ManagementValidationException(
                "client_credential_window_invalid",
                "The validity start must be before the expiration.",
                "notBeforeUtc");
        }
    }

    internal static string? ValidateRevocationReason(string? value)
    {
        var reason = value?.Trim();
        if (string.IsNullOrEmpty(reason))
        {
            return null;
        }
        if (reason.Length > IdentityDatabaseSchema.OAuthClientCredentialReasonLength
            || reason.Any(char.IsControl))
        {
            throw new ManagementValidationException(
                "client_credential_revocation_reason_invalid",
                $"The reason must be at most {IdentityDatabaseSchema.OAuthClientCredentialReasonLength} characters and cannot contain control characters.",
                "reason");
        }

        return reason;
    }

    /// <summary>
    /// Builds the short marker shown next to a credential in management UIs.
    /// It is derived from the STORED HASH, never from the plaintext secret:
    /// a suffix of the secret would put real credential material at rest, and
    /// hashing the secret directly with a fast digest would hand an attacker a
    /// cheaper guessing oracle than the PBKDF2 hash it sits beside. Feeding the
    /// (salted, 210k-iteration) hash into SHA-256 keeps the marker stable and
    /// unique per credential while staying non-reversible.
    /// </summary>
    internal static string CreateSecretFingerprint(string secretHash)
    {
        const int fingerprintCharacters = 8;
        var digest = System.Security.Cryptography.SHA256.HashData(
            System.Text.Encoding.UTF8.GetBytes(secretHash));
        return Microsoft.AspNetCore.WebUtilities.WebEncoders
            .Base64UrlEncode(digest)[..fingerprintCharacters];
    }

    internal static void ValidateClientId(string clientId)
    {
        if (string.IsNullOrWhiteSpace(clientId))
        {
            throw new ManagementValidationException(
                "client_id_required",
                "client_id is required.",
                "clientId");
        }

        if (clientId.Length > IdentityDatabaseSchema.OpenIddictClientIdLength)
        {
            throw new ManagementValidationException(
                "client_id_too_long",
                $"client_id cannot exceed {IdentityDatabaseSchema.OpenIddictClientIdLength} characters.",
                "clientId");
        }
    }

    internal static string ValidateReplacementClientSecret(string? clientSecret)
    {
        if (string.IsNullOrWhiteSpace(clientSecret))
        {
            throw new ManagementValidationException(
                "client_secret_required",
                "Provide a credential or choose automatic generation.",
                "clientSecret");
        }

        if (clientSecret.Length is < MinimumClientSecretLength or > MaximumClientSecretLength)
        {
            throw new ManagementValidationException(
                "client_secret_length_invalid",
                $"The credential must be between {MinimumClientSecretLength} and {MaximumClientSecretLength} characters.",
                "clientSecret");
        }

        if (!string.Equals(clientSecret, clientSecret.Trim(), StringComparison.Ordinal)
            || clientSecret.Any(char.IsControl))
        {
            throw new ManagementValidationException(
                "client_secret_format_invalid",
                "The credential cannot start or end with spaces or contain control characters.",
                "clientSecret");
        }

        return clientSecret;
    }
}
