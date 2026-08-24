using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Http;
using Microsoft.Net.Http.Headers;

namespace Sufficit.Identity.Management.Mcp;

/// <summary>
/// Completes the MCP authorization handshake (RFC 9728 §5.1): an
/// unauthenticated call to the MCP endpoint answers 401 with a
/// <c>WWW-Authenticate</c> header advertising the Protected Resource Metadata
/// document. Without that parameter an MCP client (Claude Code, VS Code, …)
/// cannot discover which authorization server issues tokens for this endpoint,
/// and the user has to paste an access token by hand.
///
/// The endpoint is recognized by its authorization policy rather than by path,
/// so the pointer is emitted wherever the host maps the controller.
/// </summary>
public static class McpResourceMetadataChallenge
{
    public const string PolicyName = "sufficit-identity-mcp";
    public const string DefaultRequiredScope = "identity.mcp";
    internal const string MetadataPath = "/.well-known/oauth-protected-resource";
    private const string Parameter = "resource_metadata";

    public static bool TargetsMcpEndpoint(HttpContext context) =>
        context.GetEndpoint()?.Metadata
            .GetOrderedMetadata<IAuthorizeData>()
            .Any(data => string.Equals(
                data.Policy, PolicyName, StringComparison.Ordinal))
        ?? false;

    /// <summary>
    /// Decorates the challenge the authentication handler just wrote. Called
    /// after that handler ran and before the response is flushed, so the
    /// pointer is merged into the header it produced.
    /// </summary>
    public static void Advertise(HttpContext context)
    {
        var request = context.Request;
        var metadataUrl =
            $"{request.Scheme}://{request.Host}{request.PathBase}{MetadataPath}";
        var pointer = $"{Parameter}=\"{metadataUrl}\"";
        var existing = context.Response.Headers[HeaderNames.WWWAuthenticate];
        if (existing.Count == 0)
        {
            context.Response.Headers[HeaderNames.WWWAuthenticate] =
                $"Bearer {pointer}";
            return;
        }

        // Preserve whatever the authentication handler already said (error,
        // error_description) and append the discovery pointer to its Bearer
        // challenge, so one header carries both.
        var decorated = existing
            .Where(value => !string.IsNullOrWhiteSpace(value))
            .Select(value => value!)
            .Select(value => IsUndecoratedBearer(value)
                ? Append(value, pointer)
                : value)
            .ToArray();
        context.Response.Headers[HeaderNames.WWWAuthenticate] =
            decorated.Any(value => value.Contains(
                Parameter, StringComparison.OrdinalIgnoreCase))
                ? decorated
                : [.. decorated, $"Bearer {pointer}"];
    }

    private static bool IsUndecoratedBearer(string value) =>
        value.StartsWith("Bearer", StringComparison.OrdinalIgnoreCase)
        && !value.Contains(Parameter, StringComparison.OrdinalIgnoreCase);

    /// <summary>A bare "Bearer" scheme takes a space; an existing parameter
    /// list takes a comma.</summary>
    private static string Append(string challenge, string pointer) =>
        challenge.Trim().Equals("Bearer", StringComparison.OrdinalIgnoreCase)
            ? $"Bearer {pointer}"
            : $"{challenge}, {pointer}";
}
