using System.Text.Json.Serialization;

namespace Sufficit.Identity.Management.Provisioning;

[JsonConverter(typeof(JsonStringEnumConverter<IdentityManifestChangeKind>))]
public enum IdentityManifestChangeKind
{
    Create,
    Update,
    Adopted,
    Unchanged,
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
