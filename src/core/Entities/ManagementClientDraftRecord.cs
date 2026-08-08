namespace Sufficit.Identity.Core.Entities;

/// <summary>
/// Server-side, resumable draft for OAuth/OIDC application configuration.
/// The configuration payload is protected with ASP.NET Core Data Protection;
/// secrets are never persisted in this record.
/// </summary>
public sealed class ManagementClientDraftRecord
{
    public Guid Id { get; set; }

    public string OwnerSubject { get; set; } = string.Empty;

    public string Profile { get; set; } = string.Empty;

    public string CurrentStep { get; set; } = string.Empty;

    public string Status { get; set; } = string.Empty;

    public string ProtectedPayload { get; set; } = string.Empty;

    public string Version { get; set; } = string.Empty;

    public string? CreatedClientId { get; set; }

    public DateTime CreatedAtUtc { get; set; }

    public DateTime UpdatedAtUtc { get; set; }

    public DateTime ExpiresAtUtc { get; set; }
}
