using Sufficit.Identity.Application.Security;

namespace Sufficit.Identity.STS;

/// <summary>
/// Config-driven claim-type → required-scope allowlist that closes the residual
/// over-disclosure gap (eval #10 / plan item 2.5 [M5]). When a claim type is
/// present in <see cref="ClaimToScope"/>, that claim reaches the access and
/// identity tokens ONLY if the subject was granted the mapped scope. Claim
/// types NOT in the map keep the pre-existing behavior while
/// <see cref="ClaimScopeMapOptions.IncludeUnmappedClaimsInAccessTokens"/> is
/// true. The default map protects the authorization directive claim.
/// </summary>
/// <remarks>
/// <b>Rollout model.</b> Add entries one resource server at a time: first
/// confirm every RS that consumes a claim requests the mapped scope, THEN add
/// the claim-to-scope entry. Adding an entry before the RS requests the scope
/// silently strips the claim from that RS's tokens. Mapped scopes and claims
/// are registered automatically by the STS when this option is configured.
/// </remarks>
public sealed class ClaimScopeMapOptions
{
    /// <summary>
    /// Map of claim type → scope name. When a token is being built, a claim
    /// whose type matches a key here is included in the access token ONLY if
    /// the subject's granted scopes contain the mapped value. Mapped keys and
    /// values are also advertised as custom claims/scopes in discovery.
    /// </summary>
    /// <remarks>
    /// <b>Default (finding #4 fix).</b> The Sufficit authorization directive
    /// claim (<c>directive</c>) is gated behind the <c>directives</c> scope so
    /// a client requesting only <c>openid</c> does not receive the user's full
    /// authorization directive set. An operator can add more entries or clear
    /// this map to revert to the pre-fix behavior (all claims to all tokens).
    /// </remarks>
    public Dictionary<string, string> ClaimToScope { get; init; } = new(StringComparer.Ordinal)
    {
        ["directive"] = "directives",

        // Same grant, same gate, whichever name it is stored under. Without
        // this entry a grant persisted as "entitlements" would fall to the
        // unmapped branch and — while the compatibility bridge below is on —
        // reach the access token WITHOUT the scope check, handing the user's
        // full authorization set to a client that asked only for openid. The
        // scope stays "directives" because clients already request it; the
        // point is to make the stored name irrelevant, not to add a hoop.
        ["entitlements"] = "directives",
    };

    /// <summary>
    /// Compatibility bridge for persisted claim types that are not yet mapped.
    /// Keep true while resource servers are inventoried, then set false to make
    /// <see cref="ClaimToScope"/> a strict allowlist without removing claims
    /// from existing tokens during the rollout.
    /// </summary>
    public bool IncludeUnmappedClaimsInAccessTokens { get; init; } = true;

    /// <summary>
    /// Persisted claim types that are never eligible for token release when
    /// unmapped, including while the general compatibility bridge is active.
    /// Values are claim names only; claim values are never logged.
    /// </summary>
    public HashSet<string> DeniedUnmappedClaimTypes { get; init; } = new(StringComparer.Ordinal)
    {
        "security_stamp",
        "concurrency_stamp",
        "password_hash",
        "authenticator_key",
        "recovery_codes",
    };
}
/// <summary>
/// Maps approved OAuth scopes to persisted user claims. This keeps product
/// onboarding policy configurable while the STS remains claim-type agnostic.
/// </summary>
public sealed class ScopeEntitlementOptions
{
    /// <summary>
    /// Scope name → persisted claims granted when a user approves that scope.
    /// </summary>
    /// <remarks>
    /// <b>Empty by default (eval 2026-08-30, F-2).</b> This map writes claims
    /// onto real user accounts, so a built-in entry would provision one
    /// deployment's product policy into every deployment of a service that is
    /// meant to be vendor-neutral. Which scope entitles which claim is
    /// deployment configuration — declare it under
    /// <c>Sufficit:Identity:ScopeEntitlements:Grants</c> (see
    /// <c>src/server/appsettings.json.template</c>).
    /// <para><b>Migration:</b> a deployment that relied on the previous
    /// built-in default must declare it in configuration before upgrading, or
    /// the entitlement stops being granted on scope approval. Existing claims
    /// already persisted on user accounts are untouched.</para>
    /// </remarks>
    public Dictionary<string, List<PersistedEntitlementClaimOptions>> Grants { get; init; } =
        new(StringComparer.Ordinal);
}
public sealed class PersistedEntitlementClaimOptions
{
    public string Type { get; init; } = string.Empty;

    public string Value { get; init; } = string.Empty;
}
