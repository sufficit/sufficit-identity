using System.Security.Claims;
using System.Text.Json;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Logging;
using Sufficit.Identity.Management.Mcp;

namespace Sufficit.Identity.Management.Controllers;

/// <summary>
/// Compact streamable-HTTP MCP transport for Identity self-service and Vault.
/// The bearer token is the user boundary; the transport session is additionally
/// bound to that token's subject.
/// </summary>
[ApiController]
[Authorize(Policy = "sufficit-identity-mcp")]
[Route("api/mcp")]
public sealed class McpController(
    IdentityMcpToolRegistry tools,
    McpSessionManager sessions,
    ILogger<McpController> logger) : ControllerBase
{
    private const string ProtocolVersion = "2025-06-18";
    private const string ServerName = "Sufficit Identity MCP Server";

    [HttpGet]
    public IActionResult GetServerInfo() => Ok(new
    {
        name = ServerName,
        version = GetServerVersion(),
        protocolVersion = ProtocolVersion,
        capabilities = Capabilities(),
        transport = new
        {
            type = "streamable-http",
            messageUrl = $"{Request.Scheme}://{Request.Host}{Request.PathBase}{Request.Path}"
        }
    });

    [HttpPost]
    [Consumes("application/json")]
    public async Task<IActionResult> Post(
        [FromBody] JsonElement message,
        CancellationToken cancellationToken)
    {
        Response.Headers["MCP-Protocol-Version"] = ProtocolVersion;

        var id = ReadId(message);
        if (message.ValueKind != JsonValueKind.Object
            || !message.TryGetProperty("method", out var methodElement)
            || methodElement.ValueKind != JsonValueKind.String
            || string.IsNullOrWhiteSpace(methodElement.GetString()))
        {
            return RpcError(id, -32600, "Invalid Request: method is required.",
                StatusCodes.Status400BadRequest);
        }

        var method = methodElement.GetString()!;
        var parameters = message.TryGetProperty("params", out var paramsElement)
            ? paramsElement
            : EmptyObject();
        var subject = ResolveSubject();
        if (subject is null)
        {
            return RpcError(
                id,
                -32001,
                "Authenticated MCP caller has no subject.",
                StatusCodes.Status401Unauthorized);
        }

        if (string.Equals(method, "initialize", StringComparison.Ordinal))
            return Initialize(id, parameters, subject);

        var sessionId = Request.Headers["mcp-session-id"].ToString();
        if (!sessions.Validate(sessionId, subject))
        {
            return RpcError(
                id,
                -32000,
                "Session not found, expired, or bound to another subject. Re-initialize the MCP connection.",
                StatusCodes.Status401Unauthorized);
        }

        try
        {
            return method switch
            {
                "notifications/initialized" => NoContent(),
                "ping" => RpcResult(id, new { }),
                "tools/list" => RpcResult(id, new
                {
                    tools = tools.Tools.Select(tool => new
                    {
                        name = tool.Name,
                        description = tool.Description,
                        inputSchema = tool.InputSchema
                    })
                }),
                "tools/call" => await CallToolAsync(id, parameters, subject, cancellationToken),
                _ => RpcError(id, -32601, $"Method not found: {method}.",
                    StatusCodes.Status200OK)
            };
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
            throw;
        }
        catch (Exception exception)
        {
            logger.LogError(exception, "Unhandled Identity MCP request for {Method}.", method);
            return RpcError(id, -32603, "Internal error.", StatusCodes.Status500InternalServerError);
        }
    }

    private IActionResult Initialize(
        JsonElement id,
        JsonElement parameters,
        string subject)
    {
        var requestedSessionId = Request.Headers["mcp-session-id"].ToString();
        var sessionId = sessions.Initialize(requestedSessionId, subject);
        Response.Headers["mcp-session-id"] = sessionId;

        var requestedVersion = parameters.ValueKind == JsonValueKind.Object
            && parameters.TryGetProperty("protocolVersion", out var version)
            && version.ValueKind == JsonValueKind.String
                ? version.GetString()
                : null;

        return RpcResult(id, new
        {
            protocolVersion = NegotiateProtocolVersion(requestedVersion),
            capabilities = Capabilities(),
            serverInfo = new
            {
                name = ServerName,
                version = GetServerVersion()
            }
        });
    }

    private async Task<IActionResult> CallToolAsync(
        JsonElement id,
        JsonElement parameters,
        string subject,
        CancellationToken cancellationToken)
    {
        if (parameters.ValueKind != JsonValueKind.Object
            || !parameters.TryGetProperty("name", out var nameElement)
            || nameElement.ValueKind != JsonValueKind.String
            || string.IsNullOrWhiteSpace(nameElement.GetString()))
        {
            return RpcError(id, -32602, "Invalid params: tool name is required.",
                StatusCodes.Status200OK);
        }

        var name = nameElement.GetString()!;
        var tool = tools.Find(name);
        if (tool is null)
        {
            return RpcError(id, -32601, $"Tool '{name}' not found.",
                StatusCodes.Status200OK);
        }

        var arguments = parameters.TryGetProperty("arguments", out var argumentElement)
            ? argumentElement
            : EmptyObject();
        if (arguments.ValueKind != JsonValueKind.Object)
        {
            return RpcError(id, -32602, "Invalid params: arguments must be an object.",
                StatusCodes.Status200OK);
        }

        try
        {
            var result = await tool.Handler(
                new McpToolCallContext(User, subject, HttpContext.TraceIdentifier),
                arguments,
                cancellationToken);
            return RpcResult(id, new
            {
                content = new[]
                {
                    new
                    {
                        type = "text",
                        text = JsonSerializer.Serialize(result)
                    }
                }
            });
        }
        catch (McpToolException exception)
        {
            return RpcResult(id, new
            {
                content = new[] { new { type = "text", text = exception.Message } },
                isError = true
            });
        }
        catch (ArgumentException exception)
        {
            return RpcError(id, -32602, exception.Message, StatusCodes.Status200OK);
        }
    }

    private string? ResolveSubject() =>
        User.FindFirstValue("sub")
        ?? User.FindFirstValue(ClaimTypes.NameIdentifier);

    private static object Capabilities() => new
    {
        tools = new { listChanged = false }
    };

    private static string GetServerVersion() =>
        typeof(McpController).Assembly.GetName().Version?.ToString() ?? "1.0.0";

    private static string NegotiateProtocolVersion(string? requested) =>
        requested is "2025-06-18" or "2025-03-26" or "2024-11-05"
            ? requested
            : ProtocolVersion;

    private static JsonElement EmptyObject() =>
        JsonDocument.Parse("{}").RootElement.Clone();

    private static JsonElement ReadId(JsonElement message) =>
        message.ValueKind == JsonValueKind.Object
            && message.TryGetProperty("id", out var id)
                ? id.Clone()
                : default;

    private static IActionResult RpcResult(JsonElement id, object result) =>
        new JsonResult(new { jsonrpc = "2.0", id, result });

    private static IActionResult RpcError(
        JsonElement id,
        int code,
        string message,
        int statusCode)
    {
        return new JsonResult(new
        {
            jsonrpc = "2.0",
            id,
            error = new { code, message }
        })
        {
            StatusCode = statusCode
        };
    }
}
