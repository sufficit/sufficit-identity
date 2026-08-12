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
    /// API's <c>RequireMfa</c>. <b>Default <c>true</c></b>: SCIM is a
    /// full-directory-trust surface (including password reset and account
    /// deletion), so a sensitive <c>scim</c> token requires MFA evidence.
    /// Machine-to-machine provisioning integrations using
    /// <c>client_credentials</c> cannot satisfy this requirement; they must be
    /// migrated to a separately governed integration path or use an explicit,
    /// reviewed exception with the allow-list still enabled.
    /// </summary>
    public bool RequireMfa { get; init; } = true;

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
