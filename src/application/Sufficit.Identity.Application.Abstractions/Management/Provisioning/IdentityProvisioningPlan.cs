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
    IReadOnlyList<IdentityManifestInventoryEntry> Entries)
{
    public bool HasActionRequired => Entries.Any(entry =>
        entry.Status is not IdentityManifestInventoryStatus.DeclaredCurrent);
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
