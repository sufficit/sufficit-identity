using System.Security.Claims;
using System.Text.Json;
using Sufficit.Identity.Management.Authorization;

namespace Sufficit.Identity.Management.Mcp;

/// <summary>
/// Identity of the MCP caller. Every tool operates strictly on this subject;
/// operator capabilities are consulted only when a tool explicitly targets a
/// non-personal vault context.
/// </summary>
public sealed record McpToolCallContext(
    ClaimsPrincipal Principal,
    string Subject,
    string CorrelationId)
{
    public ManagementRequestContext AsManagementContext() =>
        new(Principal, CorrelationId);
}

public sealed record McpToolDescriptor(
    string Name,
    string Description,
    object InputSchema,
    Func<McpToolCallContext, JsonElement, CancellationToken, Task<object>> Handler);

/// <summary>Thrown by tools for caller-visible failures (wrong arguments,
/// missing secret, denied context). Mapped to an MCP tool error, never a
/// protocol error.</summary>
public sealed class McpToolException(string message) : Exception(message);

public sealed class IdentityMcpToolRegistry(
    VaultMcpTools vaultTools,
    SelfServiceMcpTools selfServiceTools)
{
    private IReadOnlyList<McpToolDescriptor>? _tools;

    public IReadOnlyList<McpToolDescriptor> Tools =>
        _tools ??= [.. vaultTools.Tools, .. selfServiceTools.Tools];

    public McpToolDescriptor? Find(string name) =>
        Tools.FirstOrDefault(tool =>
            string.Equals(tool.Name, name, StringComparison.Ordinal));

    internal static string? ReadString(JsonElement args, string property) =>
        args.ValueKind == JsonValueKind.Object
        && args.TryGetProperty(property, out var value)
        && value.ValueKind == JsonValueKind.String
            ? value.GetString()
            : null;

    internal static bool ReadBool(JsonElement args, string property) =>
        args.ValueKind == JsonValueKind.Object
        && args.TryGetProperty(property, out var value)
        && value.ValueKind == JsonValueKind.True;

    internal static DateTime? ReadUtcInstant(JsonElement args, string property)
    {
        var raw = ReadString(args, property);
        if (string.IsNullOrWhiteSpace(raw)) return null;
        if (!DateTimeOffset.TryParse(raw, out var parsed))
            throw new McpToolException($"'{property}' must be an ISO-8601 instant.");
        return parsed.UtcDateTime;
    }

    internal static string RequireString(JsonElement args, string property) =>
        ReadString(args, property)
        ?? throw new McpToolException($"'{property}' is required.");
}
