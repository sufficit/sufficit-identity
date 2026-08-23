using Sufficit.Identity.Management.Authorization;

using Sufficit.Identity.Application.Security;

namespace Sufficit.Identity.Management;

/// <summary>Bindable options for the provider-management application.</summary>
public sealed class ManagementOptions
{
    public bool Enabled { get; init; }

    public string RoutePrefix { get; init; } = "api";

    /// <summary>
    /// When true (default), the management endpoints require an access token
    /// carrying the configured scope. Setting false makes the whole management
    /// API anonymous and is <b>rejected at composition time outside
    /// Development</b> (eval 2026-08-14, F-4) — use a dedicated Development
    /// environment for that migration scenario instead.
    /// </summary>
    public bool RequireAuthorization { get; init; } = true;

    public string RequiredScope { get; init; } =
        "identity.management";

    /// <summary>
    /// Scope required to reach the MCP agent surface (<c>api/mcp</c>). The
    /// policy previously accepted ANY authenticated bearer this issuer had
    /// minted, so holding a token for an unrelated client was enough to call
    /// the self-service and personal-vault tools — agent access was an ambient
    /// side effect of authentication rather than a deliberate grant. Requiring
    /// a dedicated scope makes it explicit and auditable.
    /// <para>
    /// Existing MCP clients must be granted this scope before they can call
    /// the surface again; set it to an empty string to restore the previous
    /// authenticated-only behavior during a migration window.
    /// </para>
    /// </summary>
    public string McpRequiredScope { get; init; } = "mcp";

    public ManagementAuthorizationOptions Authorization { get; init; } = new();

    /// <summary>
    /// Short-lived operator tokens used to run a provisioning command outside
    /// the embedded console. The token is deliberately attenuated to the two
    /// provisioning capabilities and never inherits administrator roles.
    /// </summary>
    public TemporaryProvisioningTokenOptions TemporaryProvisioningToken { get; init; } = new();

    /// <summary>
    /// Short-lived, explicitly attenuated bearer tokens issued by an
    /// authenticated Management operator. Query-string values in the UI may
    /// prepare an issuance request, but this policy and the canonical service
    /// remain the authorization boundary.
    /// </summary>
    public TemporaryOperatorTokenOptions TemporaryOperatorToken { get; init; } = new();

    /// <summary>
    /// Requires multi-factor evidence for sensitive provider-management
    /// operations. Deployment configuration controls this policy.
    /// </summary>
    public bool RequireMfa { get; init; } = true;

    /// <summary>
    /// Days of management audit history to keep. The table is append-only and
    /// had no retention at all, so it grew without bound for the life of the
    /// deployment — and it is written on every privileged operation, plus
    /// every refusal on the surfaces that record those.
    /// <para>
    /// One year is the default because audit history is evidence: it should
    /// outlive an incident investigation, which is usually measured in months.
    /// Set to <c>0</c> to disable pruning and keep everything, for deployments
    /// whose compliance regime requires indefinite retention and which have
    /// arranged their own archival.
    /// </para>
    /// </summary>
    public int AuditRetentionDays { get; init; } = 365;

    /// <summary>
    /// API-protection scopes that must NEVER be created via the runtime
    /// scope-management CRUD API or assigned to a client via the management-API
    /// client-create path. These scopes gate administrative surfaces (the
    /// management API itself, SCIM, and any custom privileged API); letting an
    /// operator mint one through the regular CRUD path is a privilege-
    /// escalation vector (H2/M3, eval): an operator with only
    /// <c>identity.scopes.create</c> could otherwise define
    /// <c>identity.management</c> as a custom scope and bind it to a client
    /// they control. Defaults cover the management + SCIM required scopes; add
    /// any custom privileged API scope here. These can still be declared via
    /// bootstrap/provisioning.
    /// </summary>
    public string[] ReservedApiScopes { get; init; } =
        [
            "identity.management",
            "scim",
            RetiredIdentityScopes.SkorubaIdentityAdminApi
        ];
}

public sealed class TemporaryProvisioningTokenOptions
{
    /// <summary>Enables the short-lived provisioning-token action.</summary>
    public bool Enabled { get; init; }

    /// <summary>Default lifetime when the caller does not choose one.</summary>
    public int DefaultLifetimeSeconds { get; init; } = 900;

    /// <summary>Hard upper bound for every issued token.</summary>
    public int MaximumLifetimeSeconds { get; init; } = 3600;
}

public sealed class TemporaryOperatorTokenOptions
{
    /// <summary>Enables the temporary Management-token action.</summary>
    public bool Enabled { get; init; }

    /// <summary>Default lifetime when the caller does not choose one.</summary>
    public int DefaultLifetimeSeconds { get; init; } = 900;

    /// <summary>Hard upper bound for every issued token.</summary>
    public int MaximumLifetimeSeconds { get; init; } = 3600;

    /// <summary>Maximum number of capabilities carried by one token.</summary>
    public int MaximumCapabilities { get; init; } = 24;
}
