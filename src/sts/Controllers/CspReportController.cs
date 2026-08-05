using System.Text.Json;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Logging;

namespace Sufficit.Identity.STS.Controllers;

/// <summary>
/// Receives same-origin CSP violation reports during policy calibration.
/// Only a small, sanitized projection is written to the application log so
/// query strings, fragments and arbitrary attacker-controlled JSON never
/// become part of the security log.
/// </summary>
[ApiController]
[Route("security/csp-report")]
public sealed class CspReportController(
    ILogger<CspReportController> logger) : ControllerBase
{
    private const int MaximumReportBytes = 16 * 1024;
    private const int MaximumTextLength = 256;

    [HttpPost]
    [IgnoreAntiforgeryToken]
    [RequestSizeLimit(MaximumReportBytes)]
    [Consumes("application/csp-report", "application/json", "application/reports+json")]
    public async Task<IActionResult> Report(CancellationToken cancellationToken)
    {
        JsonDocument document;
        try
        {
            document = await JsonDocument.ParseAsync(
                Request.Body,
                new JsonDocumentOptions
                {
                    AllowTrailingCommas = false,
                    CommentHandling = JsonCommentHandling.Disallow,
                    MaxDepth = 16
                },
                cancellationToken);
        }
        catch (JsonException)
        {
            return BadRequest();
        }

        using (document)
        {
            var report = FindReport(document.RootElement);
            if (report is null)
            {
                return BadRequest();
            }

            var value = report.Value;
            logger.LogWarning(
                "CSP violation: document={DocumentUri} blocked={BlockedUri} directive={Directive} source={SourceFile} line={LineNumber} column={ColumnNumber}",
                SafeUri(ReadString(value, "document-uri", "documentURL")),
                SafeUri(ReadString(value, "blocked-uri", "blockedURL")),
                SafeText(ReadString(value, "effective-directive", "effectiveDirective")),
                SafeUri(ReadString(value, "source-file", "sourceFile")),
                ReadNumber(value, "line-number", "lineNumber"),
                ReadNumber(value, "column-number", "columnNumber"));
        }

        return NoContent();
    }

    private static JsonElement? FindReport(JsonElement root)
    {
        // Legacy report-uri payload: { "csp-report": { ... } }
        if (root.ValueKind == JsonValueKind.Object
            && root.TryGetProperty("csp-report", out var legacy)
            && legacy.ValueKind == JsonValueKind.Object)
        {
            return legacy;
        }

        // Reporting API payload: [{ "type": "csp-violation", "body": { ... } }]
        if (root.ValueKind == JsonValueKind.Array)
        {
            foreach (var item in root.EnumerateArray())
            {
                if (item.ValueKind == JsonValueKind.Object
                    && item.TryGetProperty("body", out var body)
                    && body.ValueKind == JsonValueKind.Object)
                {
                    return body;
                }
            }
        }

        return null;
    }

    private static string? ReadString(JsonElement report, string legacyName, string modernName)
    {
        if (report.TryGetProperty(legacyName, out var legacy)
            && legacy.ValueKind == JsonValueKind.String)
        {
            return legacy.GetString();
        }

        return report.TryGetProperty(modernName, out var modern)
            && modern.ValueKind == JsonValueKind.String
                ? modern.GetString()
                : null;
    }

    private static long? ReadNumber(JsonElement report, string legacyName, string modernName)
    {
        if (report.TryGetProperty(legacyName, out var legacy)
            && legacy.TryGetInt64(out var legacyValue))
        {
            return legacyValue;
        }

        return report.TryGetProperty(modernName, out var modern)
            && modern.TryGetInt64(out var modernValue)
                ? modernValue
                : null;
    }

    private static string? SafeUri(string? value)
    {
        value = SafeText(value);
        if (value is null || !Uri.TryCreate(value, UriKind.Absolute, out var uri))
        {
            return value;
        }

        var sanitized = new UriBuilder(uri)
        {
            UserName = string.Empty,
            Password = string.Empty,
            Query = string.Empty,
            Fragment = string.Empty
        };

        return sanitized.Uri.GetLeftPart(UriPartial.Path);
    }

    private static string? SafeText(string? value)
    {
        if (string.IsNullOrWhiteSpace(value))
        {
            return null;
        }

        var sanitized = value.Replace('\r', ' ').Replace('\n', ' ').Trim();
        return sanitized.Length <= MaximumTextLength
            ? sanitized
            : sanitized[..MaximumTextLength];
    }
}
