namespace Sufficit.Identity.Scim;

public sealed class ScimOptions
{
    public bool Enabled { get; init; }

    /// <summary>
    /// Compatibility alias retained for one release. When
    /// <see cref="RequireScope"/> is not configured, this value controls only
    /// the OAuth scope requirement; it never disables authentication or the
    /// independent client allow-list.
    /// </summary>
    [Obsolete("Use RequireScope. This alias no longer controls client authorization.")]
    public bool RequireAuthorization { get; init; } = true;

    /// <summary>
    /// Requires <see cref="RequiredScope"/>. A null value inherits the legacy
    /// <see cref="RequireAuthorization"/> switch for rolling upgrades.
    /// </summary>
    public bool? RequireScope { get; init; }

    /// <summary>
    /// Requires an authenticated OAuth client from <see cref="AllowedClientIds"/>.
    /// This boundary is deliberately independent from scope compatibility.
    /// </summary>
    public bool RequireAllowedClient { get; init; } = true;

    /// <summary>
    /// Observe logs an allow-list miss but temporarily permits it. Enforce is
    /// fail-closed and is the secure default for new and upgraded deployments.
    /// </summary>
    public ScimClientPolicyMode ClientPolicyMode { get; init; } =
        ScimClientPolicyMode.Enforce;

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

    /// <summary>
    /// Allow-list of OAuth <c>client_id</c> values permitted to call the SCIM
    /// endpoints. SCIM operates with <b>full-directory-trust</b>: any client in
    /// this list can enumerate every user, read PII, reset any password and
    /// delete any account. <b>Default is empty (fail-closed)</b> — SCIM is
    /// inaccessible until at least one trusted provisioning client is listed.
    /// Add only dedicated, narrowly-scoped provisioning clients here; never a
    /// general-purpose application client.
    /// </summary>
    public string[] AllowedClientIds { get; init; } = [];

    public int MaxResults { get; init; } = 100;

#pragma warning disable CS0618
    internal bool EffectiveRequireScope =>
        RequireScope ?? RequireAuthorization;
#pragma warning restore CS0618
}

public enum ScimClientPolicyMode
{
    Observe,
    Enforce,
}
