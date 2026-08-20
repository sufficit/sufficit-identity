namespace Sufficit.Identity.Core.Entities;

/// <summary>
/// Provider-neutral credential registered for an OAuth client. Plaintext
/// credential material is never persisted: <see cref="SecretHash"/> contains
/// only a one-way password hash and <see cref="SecretHint"/> is a short,
/// non-sensitive suffix used to identify the credential in management UIs.
/// </summary>
public sealed class OAuthClientCredential
{
    public Guid Id { get; set; }

    /// <summary>The immutable OAuth <c>client_id</c> this credential belongs to.</summary>
    public string ClientId { get; set; } = string.Empty;

    /// <summary>Credential kind. Initially <c>shared_secret</c>.</summary>
    public string Kind { get; set; } = OAuthClientCredentialKinds.SharedSecret;

    /// <summary>Operator-supplied name such as “production 2026”.</summary>
    public string Label { get; set; } = string.Empty;

    public string SecretHash { get; set; } = string.Empty;

    public string SecretHint { get; set; } = string.Empty;

    public DateTime CreatedAtUtc { get; set; }

    public DateTime? NotBeforeUtc { get; set; }

    public DateTime? ExpiresAtUtc { get; set; }

    public DateTime? RevokedAtUtc { get; set; }

    public string? RevocationReason { get; set; }

    /// <summary>Optimistic concurrency token renewed after every mutation.</summary>
    public string ConcurrencyToken { get; set; } = string.Empty;
}

public static class OAuthClientCredentialKinds
{
    public const string SharedSecret = "shared_secret";
}
