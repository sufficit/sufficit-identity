using Sufficit.Identity.Application.Security;

namespace Sufficit.Identity.STS;

/// <summary>
/// Feature flags for legacy OAuth 2.0 grant types outside the current OAuth 2.1
/// draft baseline (Resource Owner Password Credentials and the "none"
/// grant/response type). OAuth 2.1 is still a draft, so Identity keeps these
/// compatibility switches instead of assuming that every consumer can migrate
/// immediately. Both default to <c>false</c> — secure-by-default
/// (EVALUATION-2026-07-21 §5 P0 #8). Environments that still need these grants
/// must opt-in explicitly via
/// <c>Sufficit:Identity:LegacyGrants:Password=true</c> and/or
/// <c>None=true</c> in the per-environment
/// <c>appsettings.&lt;env&gt;.json</c>, with telemetry and a migration/removal
/// decision recorded per client.
/// </summary>
public sealed class LegacyGrantsOptions
{
    /// <summary>
    /// Enables the Resource Owner Password Credentials grant
    /// (<c>grant_type=password</c>). It is outside the current OAuth 2.1 draft
    /// baseline, but remains available for existing consumers that still need
    /// compatibility. Default <c>false</c> — opt-in per environment only when
    /// a legacy client requires it, with telemetry and a migration decision.
    /// </summary>
    public bool Password { get; init; } = false;

    /// <summary>
    /// Enables the "none" grant/response type (implicit access_token without
    /// PKCE). It is outside the current OAuth 2.1 draft baseline, but remains
    /// available for existing consumers during migration. Default
    /// <c>false</c> — opt-in per environment only while migrating legacy
    /// WebForms/old-SwaggerUI clients to authorization_code + PKCE.
    /// </summary>
    public bool None { get; init; } = false;
}
