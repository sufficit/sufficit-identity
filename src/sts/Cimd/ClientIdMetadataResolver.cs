using System.Net;
using System.Text.Json;
using Microsoft.Extensions.Caching.Memory;
using Microsoft.Extensions.Logging;
using Sufficit.Identity.Application.Security;

namespace Sufficit.Identity.STS.Cimd;

/// <summary>
/// A successfully fetched-and-validated Client ID Metadata Document
/// (draft-ietf-oauth-client-id-metadata-document-02), normalized to the
/// values this STS is willing to provision.
/// </summary>
public sealed record ClientIdMetadataDocument(
    string ClientId,
    string? ClientName,
    IReadOnlyList<string> RedirectUris,
    IReadOnlyList<string> GrantTypes,
    IReadOnlyList<string> Scopes);

/// <summary>
/// Fetches and validates Client ID Metadata Documents (CIMD,
/// draft-ietf-oauth-client-id-metadata-document-02 — the registration
/// mechanism the MCP authorization spec adopted in place of DCR).
/// </summary>
/// <remarks>
/// <para>
/// The <c>client_id</c> IS an HTTPS URL serving the JSON document directly
/// (there is NO well-known path in the current draft). Enforcement mirrors
/// the draft's normative rules:
/// </para>
/// <list type="bullet">
/// <item>Identifier: HTTPS, a path component, no userinfo/query/fragment,
/// no single/double-dot path segments; comparison is exact string
/// comparison.</item>
/// <item>Fetch: 200 OK only, redirects NOT followed, response bounded by
/// <see cref="ClientIdMetadataDocumentOptions.MaxDocumentBytes"/>; the
/// destination must pass the shared SSRF policy (no RFC 6890 special-use
/// addresses — the outbound transport pins DNS resolution).</item>
/// <item>Document: <c>client_id</c> must match the identifier exactly;
/// shared-secret material (<c>client_secret</c>,
/// <c>client_secret_expires_at</c>) and shared-secret auth methods are
/// forbidden — this implementation supports PUBLIC clients only
/// (<c>token_endpoint_auth_method</c> absent or <c>none</c>), which is the
/// MCP client shape; private_key_jwt is a future extension.</item>
/// <item>Caching: only successful validations are cached for the configured
/// TTL; errors are never cached (the draft forbids it).</item>
/// </list>
/// </remarks>
public sealed class ClientIdMetadataResolver
{
    public const string HttpClientName = "cimd-client-metadata";

    private static readonly HashSet<string> ForbiddenSecretMembers = new(
        ["client_secret", "client_secret_expires_at"],
        StringComparer.Ordinal);

    private static readonly HashSet<string> SupportedGrantTypes = new(
        ["authorization_code", "refresh_token"],
        StringComparer.Ordinal);

    private readonly HttpClient _httpClient;
    private readonly ClientIdMetadataDocumentOptions _options;
    private readonly IMemoryCache _cache;
    private readonly ILogger<ClientIdMetadataResolver> _logger;

    public ClientIdMetadataResolver(
        IHttpClientFactory httpClientFactory,
        ClientIdMetadataDocumentOptions options,
        IMemoryCache cache,
        ILogger<ClientIdMetadataResolver> logger)
    {
        _httpClient = httpClientFactory.CreateClient(HttpClientName);
        _httpClient.Timeout = TimeSpan.FromSeconds(
            Math.Clamp(options.FetchTimeoutSeconds, 1, 30));
        _options = options;
        _cache = cache;
        _logger = logger;
    }

    /// <summary>
    /// True when the identifier has the CIMD URL shape (absolute HTTPS with a
    /// path) and is therefore worth a document fetch. Cheap, allocation-free
    /// first gate before any network I/O.
    /// </summary>
    public static bool IsCimdCandidate(string? clientId)
    {
        return TryParseIdentifier(clientId, out _);
    }

    /// <summary>
    /// Resolves (and caches) the metadata document for a CIMD-shaped
    /// client_id. Returns null for any non-candidate identifier, fetch
    /// failure or validation rejection — callers treat null as "not a CIMD
    /// client" and surface their normal unknown-client error.
    /// </summary>
    public async Task<ClientIdMetadataDocument?> ResolveAsync(
        string clientId,
        CancellationToken cancellationToken = default)
    {
        if (!TryParseIdentifier(clientId, out var identifier))
        {
            return null;
        }

        if (_cache.TryGetValue(clientId, out ClientIdMetadataDocument? cached))
        {
            return cached;
        }

        var document = await FetchAndValidateAsync(
            clientId, identifier, cancellationToken);
        if (document is null)
        {
            // The draft forbids caching errors/invalid documents.
            return null;
        }

        _cache.Set(
            clientId,
            document,
            TimeSpan.FromSeconds(Math.Clamp(_options.CacheTtlSeconds, 1, 3600)));
        return document;
    }

    private async Task<ClientIdMetadataDocument?> FetchAndValidateAsync(
        string clientId,
        Uri identifier,
        CancellationToken cancellationToken)
    {
        try
        {
            using var request = new HttpRequestMessage(HttpMethod.Get, identifier);
            request.Headers.Accept.ParseAdd("application/json");
            using var response = await _httpClient.SendAsync(
                request,
                HttpCompletionOption.ResponseHeadersRead,
                cancellationToken);

            // 200 OK only; the HTTP client is registered with auto-redirect
            // disabled, so 3xx lands here and is rejected as the draft
            // requires (URL shorteners are explicitly incompatible).
            if (response.StatusCode != HttpStatusCode.OK)
            {
                _logger.LogWarning(
                    "CIMD fetch for {ClientId} returned {Status}; rejecting.",
                    clientId,
                    (int)response.StatusCode);
                return null;
            }

            var payload = await ReadBoundedAsync(
                response, cancellationToken);
            if (payload is null)
            {
                return null;
            }

            return ValidateDocument(clientId, payload);
        }
        catch (Exception exception) when (
            exception is HttpRequestException
                or TaskCanceledException
                or OperationCanceledException
                or JsonException
                or InvalidOperationException)
        {
            _logger.LogWarning(
                exception,
                "CIMD fetch/parse for {ClientId} failed; rejecting.",
                clientId);
            return null;
        }
    }

    private async Task<byte[]?> ReadBoundedAsync(
        HttpResponseMessage response,
        CancellationToken cancellationToken)
    {
        var maximumBytes = Math.Clamp(_options.MaxDocumentBytes, 256, 1_048_576);
        await using var stream = await response.Content.ReadAsStreamAsync(
            cancellationToken);
        var buffer = new byte[maximumBytes + 1];
        var read = 0;
        while (read < buffer.Length)
        {
            var chunk = await stream.ReadAsync(
                buffer.AsMemory(read), cancellationToken);
            if (chunk == 0)
            {
                break;
            }
            read += chunk;
        }

        if (read > maximumBytes)
        {
            _logger.LogWarning(
                "CIMD document exceeded the {Max} byte cap; rejecting.",
                maximumBytes);
            return null;
        }

        return buffer[..read];
    }

    internal static ClientIdMetadataDocument? ValidateDocument(
        string clientId,
        byte[] payload)
    {
        using var document = JsonDocument.Parse(payload);
        var root = document.RootElement;
        if (root.ValueKind != JsonValueKind.Object)
        {
            return null;
        }

        // Exact string comparison between the requested identifier, the
        // document's client_id and the URL actually fetched.
        if (!root.TryGetProperty("client_id", out var clientIdElement)
            || clientIdElement.ValueKind != JsonValueKind.String
            || !string.Equals(
                clientIdElement.GetString(),
                clientId,
                StringComparison.Ordinal))
        {
            return null;
        }

        // Shared-secret material is forbidden in a CIMD document; this
        // implementation provisions public clients only.
        foreach (var forbidden in ForbiddenSecretMembers)
        {
            if (root.TryGetProperty(forbidden, out _))
            {
                return null;
            }
        }
        if (root.TryGetProperty("token_endpoint_auth_method", out var method)
            && method.ValueKind == JsonValueKind.String)
        {
            var value = method.GetString();
            if (!string.IsNullOrEmpty(value)
                && !string.Equals(value, "none", StringComparison.Ordinal))
            {
                return null;
            }
        }

        string? clientName = null;
        if (root.TryGetProperty("client_name", out var name)
            && name.ValueKind == JsonValueKind.String)
        {
            var value = name.GetString()?.Trim();
            clientName = string.IsNullOrEmpty(value) || value.Length > 256
                ? null
                : value;
        }

        var redirects = new List<string>();
        if (root.TryGetProperty("redirect_uris", out var redirectUris))
        {
            if (redirectUris.ValueKind != JsonValueKind.Array)
            {
                return null;
            }
            foreach (var entry in redirectUris.EnumerateArray())
            {
                if (entry.ValueKind != JsonValueKind.String
                    || !IsAllowedRedirectUri(entry.GetString()))
                {
                    return null;
                }
                redirects.Add(entry.GetString()!);
            }
        }

        var grants = new List<string>();
        if (root.TryGetProperty("grant_types", out var grantTypes))
        {
            if (grantTypes.ValueKind != JsonValueKind.Array)
            {
                return null;
            }
            foreach (var entry in grantTypes.EnumerateArray())
            {
                if (entry.ValueKind != JsonValueKind.String)
                {
                    return null;
                }
                var value = entry.GetString()!;
                if (!SupportedGrantTypes.Contains(value))
                {
                    return null;
                }
                if (!grants.Contains(value, StringComparer.Ordinal))
                {
                    grants.Add(value);
                }
            }
        }
        if (grants.Count == 0)
        {
            grants.Add("authorization_code");
        }
        if (grants.Contains("authorization_code", StringComparer.Ordinal)
            && redirects.Count == 0)
        {
            // A redirect grant needs at least one registered redirect URI.
            return null;
        }

        var scopes = new List<string>();
        if (root.TryGetProperty("scope", out var scope)
            && scope.ValueKind == JsonValueKind.String)
        {
            foreach (var value in (scope.GetString() ?? string.Empty)
                         .Split(' ',
                             StringSplitOptions.RemoveEmptyEntries
                             | StringSplitOptions.TrimEntries))
            {
                if (!scopes.Contains(value, StringComparer.Ordinal))
                {
                    scopes.Add(value);
                }
            }
        }

        return new ClientIdMetadataDocument(
            clientId,
            clientName,
            redirects,
            grants,
            scopes);
    }

    /// <summary>
    /// Redirect URIs follow the STS-wide policy used for every other
    /// dynamically provisioned client: absolute HTTPS (loopback with any
    /// port excepted for native development clients), no fragment, no
    /// userinfo.
    /// </summary>
    private static bool IsAllowedRedirectUri(string? value)
    {
        if (string.IsNullOrWhiteSpace(value))
        {
            return false;
        }
        if (!Uri.TryCreate(value, UriKind.Absolute, out var uri))
        {
            return false;
        }
        if (uri.Fragment.Length > 0 || uri.UserInfo.Length > 0)
        {
            return false;
        }
        if (uri.Scheme == Uri.UriSchemeHttps)
        {
            return true;
        }
        return uri.IsLoopback;
    }

    /// <summary>
    /// Draft §3 identifier rules: absolute HTTPS with a path component, no
    /// userinfo, no query, no fragment, and no single/double-dot path
    /// segments. A port is allowed. Root path ("<c>/</c>") is permitted (the
    /// draft says NOT RECOMMENDED, not MUST NOT).
    /// </summary>
    private static bool TryParseIdentifier(string? clientId, out Uri identifier)
    {
        identifier = null!;
        if (string.IsNullOrWhiteSpace(clientId)
            || clientId.Length > 512
            // Dot-segment rejection happens on the RAW string: System.Uri
            // normalizes "/a/../b" away before Segments is observable.
            || clientId.Contains("/../", StringComparison.Ordinal)
            || clientId.Contains("/./", StringComparison.Ordinal)
            || clientId.EndsWith("/..", StringComparison.Ordinal)
            || clientId.EndsWith("/.", StringComparison.Ordinal)
            || !Uri.TryCreate(clientId, UriKind.Absolute, out var parsed))
        {
            return false;
        }

        if (!string.Equals(
                parsed.Scheme,
                Uri.UriSchemeHttps,
                StringComparison.OrdinalIgnoreCase)
            || parsed.UserInfo.Length > 0
            || parsed.Query.Length > 0
            || parsed.Fragment.Length > 0
            || string.IsNullOrEmpty(parsed.PathAndQuery))
        {
            return false;
        }

        // MUST have a path component. "https://host" and "https://host/"
        // are indistinguishable after Uri normalization (both give "/"),
        // and "/" is explicitly permitted above.
        var segments = parsed.Segments;
        foreach (var segment in segments)
        {
            if (segment is "." or "..")
            {
                return false;
            }
        }

        // The shared SSRF policy rejects literal special-use addresses;
        // hostname-based resolution is pinned by the outbound transport.
        if (!PublicHttpsUriPolicy.IsAllowed(parsed))
        {
            return false;
        }

        identifier = parsed;
        return true;
    }
}
