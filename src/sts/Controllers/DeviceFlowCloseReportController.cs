using System.Text.Json.Serialization;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.RateLimiting;
using Microsoft.Extensions.Logging;

namespace Sufficit.Identity.STS.Controllers;

/// <summary>
/// Receives a bounded, privacy-safe diagnostic trail for the terminal device
/// authorization page. Browsers differ in which script-created tabs they let
/// a user gesture close, and COOP can remove window.opener before that gesture.
/// No device code, token, user identifier or return URL is accepted here.
/// </summary>
[ApiController]
[Authorize]
[Route("security/device-flow-close-report")]
public sealed class DeviceFlowCloseReportController(
    ILogger<DeviceFlowCloseReportController> logger) : ControllerBase
{
    private const int MaximumReportBytes = 2 * 1024;
    private const int MaximumUserAgentLength = 256;

    private static readonly HashSet<string> AllowedEvents = new(StringComparer.Ordinal)
    {
        "close-control-initialized",
        "manual-close-required",
        "close-requested",
        "script-close-attempted",
        "script-close-succeeded",
        "script-close-blocked",
        "script-close-error",
        "close-pagehide-observed",
        "manual-close-instructions-shown"
    };

    private static readonly HashSet<string> AllowedStrategies = new(StringComparer.Ordinal)
    {
        "direct",
        "top",
        "retargeted",
        "all"
    };

    private static readonly HashSet<string> AllowedReasons = new(StringComparer.Ordinal)
    {
        "tab-not-script-opened",
        "close-blocked",
        "exception"
    };

    private static readonly HashSet<string> AllowedVisibilityStates = new(StringComparer.Ordinal)
    {
        "visible",
        "hidden",
        "prerender",
        "unloaded",
        "unknown"
    };

    [HttpPost]
    [IgnoreAntiforgeryToken]
    [EnableRateLimiting("device-information")]
    [RequestSizeLimit(MaximumReportBytes)]
    [Consumes("application/json")]
    public IActionResult Report([FromBody] DeviceFlowCloseReport? report)
    {
        if (report is null
            || !AllowedEvents.Contains(report.Event)
            || (report.Strategy is not null && !AllowedStrategies.Contains(report.Strategy))
            || (report.Reason is not null && !AllowedReasons.Contains(report.Reason))
            || !AllowedVisibilityStates.Contains(report.Visibility)
            || report.HistoryLength is < 0 or > 100)
        {
            return BadRequest();
        }

        logger.LogInformation(
            "Device flow close: event={Event} strategy={Strategy} reason={Reason} opener={HasOpener} history={HistoryLength} activation={UserActivation} visibility={Visibility} persisted={Persisted} userAgent={UserAgent}",
            report.Event,
            report.Strategy,
            report.Reason,
            report.HasOpener,
            report.HistoryLength,
            report.UserActivation,
            report.Visibility,
            report.Persisted,
            SafeUserAgent(Request.Headers.UserAgent.ToString()));

        return NoContent();
    }

    private static string? SafeUserAgent(string? value)
    {
        if (string.IsNullOrWhiteSpace(value))
        {
            return null;
        }

        var sanitized = value.Replace('\r', ' ').Replace('\n', ' ').Trim();
        return sanitized.Length <= MaximumUserAgentLength
            ? sanitized
            : sanitized[..MaximumUserAgentLength];
    }
}

public sealed record DeviceFlowCloseReport
{
    [JsonPropertyName("event")]
    public string Event { get; init; } = string.Empty;

    [JsonPropertyName("strategy")]
    public string? Strategy { get; init; }

    [JsonPropertyName("reason")]
    public string? Reason { get; init; }

    [JsonPropertyName("hasOpener")]
    public bool HasOpener { get; init; }

    [JsonPropertyName("historyLength")]
    public int HistoryLength { get; init; }

    [JsonPropertyName("userActivation")]
    public bool UserActivation { get; init; }

    [JsonPropertyName("visibility")]
    public string Visibility { get; init; } = "unknown";

    [JsonPropertyName("persisted")]
    public bool? Persisted { get; init; }
}
