namespace Sufficit.Identity.Core.Entities;

/// <summary>
/// Provisioning group defined by SCIM. It is deliberately separate from
/// ASP.NET Identity roles: a SCIM group has no provider-authorization meaning
/// unless a deployment explicitly maps it outside this canonical store.
/// </summary>
public sealed class ScimGroup
{
    public string Id { get; set; } = string.Empty;

    public string? ExternalId { get; set; }

    public string DisplayName { get; set; } = string.Empty;

    public DateTime CreatedAtUtc { get; set; }

    public DateTime UpdatedAtUtc { get; set; }

    public string ConcurrencyStamp { get; set; } = string.Empty;

    public ICollection<ScimGroupUserMember> UserMembers { get; set; } =
        new List<ScimGroupUserMember>();

    public ICollection<ScimGroupGroupMember> GroupMembers { get; set; } =
        new List<ScimGroupGroupMember>();
}

public sealed class ScimGroupUserMember
{
    public string GroupId { get; set; } = string.Empty;

    public string UserId { get; set; } = string.Empty;

    public ScimGroup Group { get; set; } = null!;

    public ApplicationUser User { get; set; } = null!;
}

public sealed class ScimGroupGroupMember
{
    public string GroupId { get; set; } = string.Empty;

    public string MemberGroupId { get; set; } = string.Empty;

    public ScimGroup Group { get; set; } = null!;

    public ScimGroup MemberGroup { get; set; } = null!;
}
