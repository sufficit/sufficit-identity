using System.Text.Json.Serialization;

namespace Sufficit.Identity.Management.Provisioning;

[JsonConverter(typeof(JsonStringEnumConverter<IdentityManifestChangeKind>))]
public enum IdentityManifestChangeKind
{
    Create,
    Update,
    Adopted,
    Observed,
    Unchanged,
}

[JsonConverter(typeof(JsonStringEnumConverter<IdentityManifestInventoryStatus>))]
public enum IdentityManifestInventoryStatus
{
    DeclaredMissing,
    DeclaredCurrent,
    DeclaredDrifted,
    DeclaredUnmanaged,
    DeclaredOwnedByAnotherManifest,
    ManagedButUndeclared,
    UnmanagedAndUndeclared,
}

public sealed record IdentityManifestInventoryEntry(
    string ClientId,
    IdentityManifestInventoryStatus Status,
    string? ManifestIdentity = null,
    int? SchemaVersion = null);

public sealed record IdentityProvisioningInventory(
    IReadOnlyList<IdentityManifestInventoryEntry> Entries,
    string? ManifestId = null,
    DateTimeOffset? GeneratedAtUtc = null,
    string? CorrelationId = null)
{
    public bool HasActionRequired => Entries.Any(entry =>
        entry.Status is not IdentityManifestInventoryStatus.DeclaredCurrent);

    /// <summary>
    /// Redacted, operator-friendly counts that can be reviewed and approved
    /// without scanning the full client list. Keys are enum names so the
    /// report remains stable for shell/JSON consumers.
    /// </summary>
    public IReadOnlyDictionary<string, int> StatusCounts =>
        Entries
            .GroupBy(entry => entry.Status.ToString(), StringComparer.Ordinal)
            .ToDictionary(
                group => group.Key,
                group => group.Count(),
                StringComparer.Ordinal);
}

public sealed record IdentityManifestChange(
    string ResourceType,
    string Identifier,
    IdentityManifestChangeKind Kind);

public sealed record IdentityProvisioningPlan(
    IReadOnlyList<IdentityManifestChange> Changes)
{
    public bool HasChanges => Changes.Any(change =>
        change.Kind is IdentityManifestChangeKind.Create
            or IdentityManifestChangeKind.Update
            or IdentityManifestChangeKind.Adopted);
}
