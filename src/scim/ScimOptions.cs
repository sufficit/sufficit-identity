namespace Sufficit.Identity.Scim;

public sealed class ScimOptions
{
    public bool Enabled { get; init; }

    public bool RequireAuthorization { get; init; } = true;

    public string RequiredScope { get; init; } = "scim";

    /// <summary>
    /// When <c>true</c>, every SCIM request must carry an <c>amr</c> claim
    /// proving multi-factor authentication (RFC 8176), mirroring the management
    /// API's <c>RequireMfa</c>. <b>Default <c>false</c></b>: SCIM is most often
    /// driven by machine-to-machine provisioning integrations (client_credentials),
    /// which by definition cannot perform MFA. Enable only when SCIM is exposed
    /// to delegated (human) flows and the full-directory-trust surface of SCIM
    /// (password reset, account delete) must require a second factor. When
    /// false, restrict the <c>scim</c> scope to a single dedicated provisioning
    /// client instead.
    /// </summary>
    public bool RequireMfa { get; init; } = false;

    public int MaxResults { get; init; } = 100;
}
