using System.Security.Claims;
using Sufficit.Identity.Application.Security;

namespace Sufficit.Identity.STS;

/// <summary>
/// Helpers for firing CAEP security events from the account/management/SCIM
/// surfaces. Keeps the session-id extraction and best-effort dispatch
/// envelope in one place so every call site behaves identically.
/// </summary>
internal static class SecurityEventTriggerExtensions
{
    /// <summary>
    /// The OIDC session-id claim used by the STS principal factory
    /// (<see cref="OidcSessionClaimsPrincipalFactory"/>). Same value, inlined
    /// here so this helper has no dependency on the internal constant.
    /// </summary>
    private const string SessionIdClaimType = "sid";

    /// <summary>
    /// Fires a CAEP <c>credential-change</c> event for the subject identified
    /// by <paramref name="principal"/>, swallowing delivery failures. Safe to
    /// call from any mutation path after the business operation succeeded.
    /// </summary>
    public static Task CredentialChangedAsync(
        this ISecurityEventTrigger trigger,
        ClaimsPrincipal? principal,
        string subject,
        CaepCredentialChange change,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(trigger);
        return trigger.CredentialChangedAsync(
            subject,
            principal?.FindFirst(SessionIdClaimType)?.Value,
            change,
            cancellationToken);
    }

    /// <summary>
    /// Fires a CAEP <c>device-change</c> event for the subject identified by
    /// <paramref name="principal"/>, swallowing delivery failures.
    /// </summary>
    public static Task DeviceChangedAsync(
        this ISecurityEventTrigger trigger,
        ClaimsPrincipal? principal,
        string subject,
        CaepDeviceChange change,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(trigger);
        return trigger.DeviceChangedAsync(
            subject,
            principal?.FindFirst(SessionIdClaimType)?.Value,
            change,
            cancellationToken);
    }

    /// <summary>
    /// Fires a CAEP <c>assurance-level-change</c> event for the subject
    /// identified by <paramref name="principal"/>, swallowing delivery
    /// failures.
    /// </summary>
    public static Task AssuranceLevelChangedAsync(
        this ISecurityEventTrigger trigger,
        ClaimsPrincipal? principal,
        string subject,
        CaepAssuranceLevelChange change,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(trigger);
        return trigger.AssuranceLevelChangedAsync(
            subject,
            principal?.FindFirst(SessionIdClaimType)?.Value,
            change,
            cancellationToken);
    }
}
