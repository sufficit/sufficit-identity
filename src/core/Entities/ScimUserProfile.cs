namespace Sufficit.Identity.Core.Entities;

/// <summary>
/// SCIM-specific profile attributes that are not part of ASP.NET Core
/// Identity. Authentication fields remain on <see cref="ApplicationUser"/>.
/// </summary>
public sealed class ScimUserProfile
{
    public string UserId { get; set; } = string.Empty;

    public string? ExternalId { get; set; }

    public string? DisplayName { get; set; }

    public string? FormattedName { get; set; }

    public string? FamilyName { get; set; }

    public string? GivenName { get; set; }

    public string? MiddleName { get; set; }

    public string? HonorificPrefix { get; set; }

    public string? HonorificSuffix { get; set; }

    public string? Title { get; set; }

    public string? UserType { get; set; }

    public string? PreferredLanguage { get; set; }

    public string? Locale { get; set; }

    public string? Timezone { get; set; }

    public DateTime CreatedAtUtc { get; set; }

    public DateTime UpdatedAtUtc { get; set; }

    public ApplicationUser User { get; set; } = null!;
}
