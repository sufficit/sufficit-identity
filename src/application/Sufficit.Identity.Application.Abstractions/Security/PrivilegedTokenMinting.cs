using System.Security.Claims;

namespace Sufficit.Identity.Application.Security;

/// <summary>
/// The single privileged-token minting boundary (A3, eval 2026-08-14).
/// Reference access tokens minted OUTSIDE the regular grant pipeline —
/// personal tokens, temporary provisioning tokens and temporary operator
/// tokens — used to each hand-roll the same OpenIddict dispatch
/// (transaction, GenerateTokenContext with reference + persisted payload,
/// rejection handling) with subtly divergent issuer/claim/destination rules.
/// Minting now happens in exactly one place; each caller keeps only its own
/// issuance POLICY (who may mint, which capabilities, which lifetime) and
/// passes a fully-decided request.
/// </summary>
public interface IPrivilegedTokenMintingService
{
    /// <summary>
    /// Mints a reference access token from a decided request: identity
    /// claims, scopes, resources (resolved from the scopes unless
    /// overridden), lifetime and destinations are applied uniformly.
    /// </summary>
    Task<PrivilegedTokenMint> MintAsync(
        PrivilegedTokenMintRequest request,
        CancellationToken cancellationToken = default);

    /// <summary>
    /// Low-level principal-based mint for callers that build the principal
    /// themselves (e.g. personal tokens, which project live user state).
    /// Applies the same dispatch contract as <see cref="MintAsync"/>.
    /// </summary>
    Task<PrivilegedTokenMint> MintPrincipalAsync(
        ClaimsPrincipal principal,
        bool createEntry = true,
        bool referenceToken = true,
        bool persistPayload = true,
        CancellationToken cancellationToken = default);

    /// <summary>
    /// Stamps the protocol scaffolding every privileged token carries onto a
    /// caller-built identity (B1): granted scopes as both the OpenIddict
    /// scope set and the public <c>scope</c> claim, resources as both the
    /// private resource set and the public <c>aud</c> claim, lifetime, issuer
    /// and claim destinations.
    /// </summary>
    /// <remarks>
    /// <see cref="MintAsync"/> applies exactly this, so a caller that builds
    /// its own identity — a personal token projects live user state, which no
    /// flat request can express — gets the same token shape instead of a
    /// second copy of these rules that drifts on the next protocol change.
    /// The scaffolding is deliberately not a mint: the caller still decides
    /// when to dispatch, and with which persistence flags.
    /// </remarks>
    ValueTask ApplyScaffoldingAsync(
        ClaimsIdentity identity,
        PrivilegedTokenScaffold scaffold,
        CancellationToken cancellationToken = default);
}

/// <summary>
/// The decided protocol shape of a privileged token, applied verbatim by
/// <see cref="IPrivilegedTokenMintingService.ApplyScaffoldingAsync"/>.
/// </summary>
public sealed record PrivilegedTokenScaffold(
    IReadOnlyList<string> Scopes,
    /// <summary>
    /// Stamped as OpenIddict's private issuer metadata. Resolved by the
    /// CALLER so each surface keeps its own missing-issuer error contract.
    /// </summary>
    string Issuer,
    DateTimeOffset CreatedAtUtc,
    DateTimeOffset ExpiresAtUtc,
    /// <summary>
    /// Audience/resource claims. When null, resources are resolved from the
    /// scopes through the OpenIddict scope manager. Pass an empty list to
    /// scaffold an audience-less token.
    /// </summary>
    IReadOnlyList<string>? Resources = null,
    /// <summary>
    /// Claim-destination selector; defaults to every claim reaching the
    /// access token only — these are bearer references, never id tokens.
    /// </summary>
    Func<Claim, IEnumerable<string>>? Destinations = null);

/// <summary>
/// A fully-decided mint request. The service applies these verbatim —
/// authorization, attenuation and lifetime policy belong to the caller.
/// </summary>
public sealed record PrivilegedTokenMintRequest(
    /// <summary>Authentication type stamped on the identity (auditing aid).</summary>
    string AuthenticationType,
    string Subject,
    /// <summary>Logical client identifier stamped as <c>client_id</c>.</summary>
    string ClientId,
    string? DisplayName,
    DateTimeOffset CreatedAtUtc,
    DateTimeOffset ExpiresAtUtc,
    IReadOnlyList<string> Scopes,
    /// <summary>
    /// Audience/resource claims. When null, resources are resolved from the
    /// scopes through the OpenIddict scope manager (and also persisted as
    /// private audience metadata so introspection identifies the audiences).
    /// Pass an empty list to mint an audience-less token.
    /// </summary>
    IReadOnlyList<string>? Resources,
    /// <summary>
    /// Additional string claims copied verbatim (markers, permission
    /// bundles). The public <c>scope</c> claim and OpenIddict's private
    /// issuer/creation/expiration metadata are applied by the service.
    /// </summary>
    IReadOnlyDictionary<string, string> StringClaims,
    /// <summary>
    /// Authentication-evidence claims (amr, auth_time, acr, aal…) copied
    /// from the authorizing operator principal.
    /// </summary>
    IEnumerable<Claim> EvidenceClaims,
    /// <summary>
    /// Claim-destination selector; defaults to every claim reaching the
    /// access token only — these are bearer references, never id tokens.
    /// </summary>
    Func<Claim, IEnumerable<string>>? Destinations = null,
    /// <summary>
    /// Issuer stamped as OpenIddict's private issuer metadata. Resolved by
    /// the CALLER so each surface keeps its own missing-issuer error
    /// contract (a shared silent default would hide misconfiguration).
    /// </summary>
    string? Issuer = null);

/// <summary>The minted credential. The token value is shown exactly once.</summary>
public sealed record PrivilegedTokenMint(
    string TokenId,
    string Token,
    DateTimeOffset CreatedAtUtc,
    DateTimeOffset ExpiresAtUtc);
