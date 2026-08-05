namespace Sufficit.Identity.Scim;

public sealed class ScimOptions
{
    public bool Enabled { get; init; }

    public bool RequireAuthorization { get; init; } = true;

    public string RequiredScope { get; init; } = "scim";

    public int MaxResults { get; init; } = 100;
}
