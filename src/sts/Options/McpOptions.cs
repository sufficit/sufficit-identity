using Sufficit.Identity.Application.Security;

namespace Sufficit.Identity.STS;

/// <summary>
/// MCP (Model Context Protocol) / agent-AI resource-server configuration
/// (Onda 4). Configures the STS to serve as the authorization server for MCP
/// servers and other agent resource servers: RFC 8707 resource indicators
/// (audience binding), RFC 9728 protected-resource metadata, and (opt-in)
/// RFC 7591 Dynamic Client Registration.
/// </summary>
public sealed class McpOptions
{
    /// <summary>
    /// OAuth scope required by the Identity MCP and the subject-bound personal
    /// Vault HTTP surface. This is deliberately separate from
    /// <c>identity.management</c>: it grants self-service access only and never
    /// authorizes shared Vault contexts or operator capabilities.
    /// </summary>
    public string RequiredScope { get; init; } = "identity.mcp";

    /// <summary>
    /// Clients whose user tokens implicitly receive
    /// <see cref="RequiredScope"/>. The server also provisions the matching
    /// OpenIddict client permission at startup. Empty by default: which
    /// applications a deployment trusts this far is deployment configuration,
    /// never a built-in. Keep the allowlist narrow — adding a client grants
    /// every signed-in user of that client access to their own Identity MCP
    /// and personal Vault.
    /// </summary>
    public HashSet<string> ImplicitClientIds { get; init; } =
        new(StringComparer.Ordinal);

    /// <summary>
    /// Resource/audience URIs the STS recognizes as valid <c>resource</c>
    /// indicator targets (RFC 8707, item 4.2). These are registered with
    /// OpenIddict so <c>resource</c> parameters are accepted (without this,
    /// OpenIddict rejects unknown resources with <c>invalid_target</c>). A
    /// client must ALSO be granted the matching <c>oi_rprm</c> permission
    /// (<c>Permissions.Prefixes.Resource + uri</c>) to request one. Each entry
    /// typically points to an MCP server (e.g.
    /// <c>https://mcp.example.com</c>). Empty by default.
    /// </summary>
    public List<string> Resources { get; init; } = new();

    /// <summary>
    /// When <c>true</c>, exposes the RFC 9728
    /// <c>/.well-known/oauth-protected-resource</c> metadata document pointing
    /// resource servers (MCP) to this STS as their authorization server.
    /// Default <c>true</c>: serving the metadata is cheap and harmless (it only
    /// advertises the AS location; actual resource servers decide whether to
    /// trust it). Disable only if the STS is never an MCP/agent AS.
    /// </summary>
    public bool ProtectedResourceMetadataEnabled { get; init; } = true;

    /// <summary>
    /// Dynamic Client Registration (RFC 7591) — opt-in (default <c>false</c>).
    /// When enabled, exposes <c>/connect/register</c> for clients (including
    /// MCP clients) to self-register. Gated: requires an initial access token
    /// by default (see <see cref="DcrRequireInitialAccessToken"/>). DCR is a
    /// high-risk surface if open; enable deliberately.
    /// </summary>
    public DcrOptions Dcr { get; init; } = new();

    /// <summary>
    /// Client ID Metadata Documents (draft-ietf-oauth-client-id-metadata-
    /// document, the registration mechanism the MCP authorization spec of
    /// 2025-11-25+ relies on) — opt-in (default <c>false</c>). The client_id
    /// IS an HTTPS URL; the STS fetches the metadata document from that URL
    /// directly on first use and provisions a public PKCE client. See
    /// <see cref="ClientIdMetadataDocumentOptions"/>.
    /// </summary>
    public ClientIdMetadataDocumentOptions ClientIdMetadataDocuments
    {
        get; init;
    } = new();
}
/// <summary>
/// Dynamic Client Registration (RFC 7591) options — item 4.3.
/// </summary>
public sealed class DcrOptions
{
    /// <summary>
    /// Master switch for the <c>/connect/register</c> endpoint. Default
    /// <c>false</c> (secure-by-default — DCR is an open-registration surface).
    /// </summary>
    public bool Enabled { get; init; } = false;

    /// <summary>
    /// When <c>true</c>, the <c>/connect/register</c> endpoint requires a
    /// valid initial access token (bearer) in the Authorization header. Default
    /// <c>true</c> — without it, anyone can register a client. The token is
    /// validated against <see cref="InitialAccessToken"/>; leave that empty to
    /// disable the endpoint entirely (Enabled must be true AND a token
    /// configured for DCR to actually accept requests).
    /// </summary>
    public bool RequireInitialAccessToken { get; init; } = true;

    /// <summary>
    /// The static initial access token accepted by <c>/connect/register</c>
    /// when <see cref="RequireInitialAccessToken"/> is true. Configure via User
    /// Secrets / env var in real environments — NEVER commit a real value.
    /// Empty = endpoint rejects all requests (even when Enabled).
    /// </summary>
    public string InitialAccessToken { get; init; } = "";

    /// <summary>
    /// Required expiry for the bootstrap credential when DCR is enabled.
    /// Provision a new credential/expiry for each registration ceremony.
    /// </summary>
    public DateTimeOffset? InitialAccessTokenExpiresAtUtc { get; init; }

    public bool InitialAccessTokenSingleUse { get; init; } = true;

    /// <summary>
    /// Deprecated migration adapters, <b>secure-by-default since eval
    /// 2026-08-14 (F-8)</b>: the class previously defaulted both to true and
    /// only the shipped appsettings template overrode them to false, so any
    /// deployment composing the options without that template silently
    /// accepted caller-chosen client ids and secrets. Secure registrations
    /// use server-issued identifiers and one-time plaintext secrets; flip
    /// these only for a bounded, documented legacy-registration window.
    /// </summary>
    public bool AllowCallerSuppliedClientIds { get; init; } = false;

    public bool AllowCallerSuppliedSecrets { get; init; } = false;

    /// <summary>
    /// Grant types that a dynamically registered client may request. Defaults
    /// to the interactive OAuth 2.1 grants; privileged and legacy grants must
    /// be enabled deliberately.
    /// </summary>
    public HashSet<string> AllowedGrantTypes { get; init; } = new(StringComparer.Ordinal)
    {
        OpenIddict.Abstractions.OpenIddictConstants.GrantTypes.AuthorizationCode,
        OpenIddict.Abstractions.OpenIddictConstants.GrantTypes.RefreshToken,
    };

    /// <summary>
    /// Scopes that a dynamically registered client may request. Custom API or
    /// administrative scopes must be explicitly added by the operator.
    /// </summary>
    public HashSet<string> AllowedScopes { get; init; } = new(StringComparer.Ordinal)
    {
        OpenIddict.Abstractions.OpenIddictConstants.Scopes.OpenId,
        OpenIddict.Abstractions.OpenIddictConstants.Scopes.Profile,
        OpenIddict.Abstractions.OpenIddictConstants.Scopes.Email,
        OpenIddict.Abstractions.OpenIddictConstants.Scopes.OfflineAccess,
    };

    /// <summary>
    /// Scopes granted to an anonymous registration (one made without an
    /// initial access token). This is deliberately a second, tighter allowlist
    /// than <see cref="AllowedScopes"/>: open registration is acceptable for an
    /// agent that only signs the user in and talks to MCP, and unacceptable for
    /// anything that reaches an API scope. A request asking for a scope outside
    /// this set is rejected rather than silently narrowed, so the client learns
    /// what it actually got.
    ///
    /// Anonymous registrations are additionally forced to be public
    /// (PKCE, no client secret) and limited to the interactive grants — see
    /// <see cref="AnonymousGrantTypes"/>.
    /// </summary>
    public HashSet<string> AnonymousScopes { get; init; } = new(StringComparer.Ordinal)
    {
        OpenIddict.Abstractions.OpenIddictConstants.Scopes.OpenId,
        OpenIddict.Abstractions.OpenIddictConstants.Scopes.Profile,
        // Interactive relying parties such as Forgejo need the standard email
        // claim to create or link the local account. This remains identity
        // metadata only; anonymous DCR still cannot request API scopes.
        OpenIddict.Abstractions.OpenIddictConstants.Scopes.Email,
        OpenIddict.Abstractions.OpenIddictConstants.Scopes.OfflineAccess,
    };

    /// <summary>
    /// Grants an anonymous registration may request. Interactive only: an
    /// unauthenticated caller must never obtain a client that can mint tokens
    /// on its own (client_credentials) or handle user passwords.
    /// </summary>
    public HashSet<string> AnonymousGrantTypes { get; init; } = new(StringComparer.Ordinal)
    {
        OpenIddict.Abstractions.OpenIddictConstants.GrantTypes.AuthorizationCode,
        OpenIddict.Abstractions.OpenIddictConstants.GrantTypes.RefreshToken,
    };
}
/// <summary>
/// Client ID Metadata Documents (CIMD,
/// draft-ietf-oauth-client-id-metadata-document-02). The client_id is an
/// HTTPS URL serving a JSON metadata document; the authorization server
/// fetches it directly (no well-known path), enforcing the draft's security
/// rules: exact client_id string match, public clients only (shared secrets
/// are forbidden), 200-only responses without redirects, a bounded document
/// size, and no caching of failed fetches. This replaces DCR for MCP-style
/// clients (the MCP authorization spec deprecated DCR in favor of CIMD) and
/// removes the registration endpoint + initial-access-token ceremony.
/// </summary>
public sealed class ClientIdMetadataDocumentOptions
{
    public bool Enabled { get; init; } = false;

    /// <summary>Per-fetch timeout. Documents are small; keep it tight.</summary>
    public int FetchTimeoutSeconds { get; init; } = 3;

    /// <summary>
    /// Hard cap on bytes read from the document (spec recommends a 5 KB
    /// maximum). Larger responses are rejected, never truncated-then-parsed.
    /// </summary>
    public int MaxDocumentBytes { get; init; } = 5120;

    /// <summary>
    /// How long a successfully resolved document is cached before the next
    /// first-use re-fetches it (RFC 9111 honoring is a bounded fixed TTL in
    /// this implementation; documents are client-controlled content).
    /// </summary>
    public int CacheTtlSeconds { get; init; } = 300;
}
