using System.Security.Claims;
using Microsoft.Extensions.Logging;
using OpenIddict.Abstractions;
using static OpenIddict.Abstractions.OpenIddictConstants;

namespace Sufficit.Identity.STS;

public interface IApplicationClaimDestinationPolicy
{
    IReadOnlyDictionary<string, string> MappedClaimScopes { get; }

    IEnumerable<string> GetDestinations(
        Claim claim,
        bool includeIdentityToken);
}

internal sealed class ApplicationClaimDestinationPolicy(
    ClaimScopeMapOptions options,
    ILogger<ApplicationClaimDestinationPolicy>? logger = null,
    ISecurityDecisionTelemetry? telemetry = null) : IApplicationClaimDestinationPolicy
{
    public IReadOnlyDictionary<string, string> MappedClaimScopes =>
        options.ClaimToScope;

    public IEnumerable<string> GetDestinations(
        Claim claim,
        bool includeIdentityToken)
    {
        if (options.ClaimToScope.TryGetValue(claim.Type, out var requiredScope))
        {
            if (!claim.Subject!.HasScope(requiredScope)) yield break;

            yield return Destinations.AccessToken;
            if (includeIdentityToken)
                yield return Destinations.IdentityToken;
            yield break;
        }

        if (options.DeniedUnmappedClaimTypes.Contains(claim.Type))
        {
            telemetry?.Record(
                "claim_release",
                "enforce",
                wouldReject: true,
                rejected: true,
                ["sensitive_unmapped"]);
            logger?.LogWarning(
                "Suppressed sensitive unmapped claim type {ClaimType} from token release.",
                claim.Type);
            yield break;
        }

        if (options.IncludeUnmappedClaimsInAccessTokens)
            yield return Destinations.AccessToken;
    }
}

public interface ITokenIssuancePolicyKernel
{
    IReadOnlyList<string> Attenuate(
        IEnumerable<string> requested,
        IEnumerable<string> delegated,
        IEnumerable<string> serverAllowed,
        bool inheritDelegatedWhenRequestIsEmpty);
}

internal sealed class TokenIssuancePolicyKernel : ITokenIssuancePolicyKernel
{
    public IReadOnlyList<string> Attenuate(
        IEnumerable<string> requested,
        IEnumerable<string> delegated,
        IEnumerable<string> serverAllowed,
        bool inheritDelegatedWhenRequestIsEmpty)
    {
        var delegatedSet = delegated
            .Where(value => !string.IsNullOrWhiteSpace(value))
            .ToHashSet(StringComparer.Ordinal);
        var allowedSet = serverAllowed
            .Where(value => !string.IsNullOrWhiteSpace(value))
            .ToHashSet(StringComparer.Ordinal);
        var requestedSet = requested
            .Where(value => !string.IsNullOrWhiteSpace(value))
            .ToHashSet(StringComparer.Ordinal);
        var source = requestedSet.Count == 0 && inheritDelegatedWhenRequestIsEmpty
            ? delegatedSet
            : requestedSet;

        return source
            .Where(delegatedSet.Contains)
            .Where(allowedSet.Contains)
            .Order(StringComparer.Ordinal)
            .ToArray();
    }
}

public sealed record PersonalTokenIssuanceContext(
    string Subject,
    string? CallerClientId,
    IReadOnlyCollection<string> CallerScopes,
    IReadOnlyCollection<string> RequestedScopes,
    IReadOnlyCollection<string> ServerAllowedScopes,
    DateTimeOffset? AuthenticationTime,
    DateTimeOffset Now,
    DateTimeOffset Expiration,
    bool HasSenderConstraint,
    bool HasMfaEvidence = false);

public sealed record PersonalTokenIssuanceDecision(
    bool ShouldReject,
    bool WouldReject,
    IReadOnlyList<string> EffectiveScopes,
    string? ErrorCode,
    IReadOnlyList<string> ReasonCodes);

public interface IPersonalTokenIssuancePolicy
{
    PersonalTokenIssuanceDecision Evaluate(PersonalTokenIssuanceContext context);
}

internal sealed class PersonalTokenIssuancePolicy(
    PersonalTokenIssuanceOptions options,
    ITokenIssuancePolicyKernel kernel,
    ILogger<PersonalTokenIssuancePolicy> logger,
    ISecurityDecisionTelemetry? telemetry = null) : IPersonalTokenIssuancePolicy
{
    public PersonalTokenIssuanceDecision Evaluate(PersonalTokenIssuanceContext context)
    {
        ArgumentNullException.ThrowIfNull(context);
        var reasons = new List<string>();
        var strictScopes = kernel.Attenuate(
            context.RequestedScopes,
            context.CallerScopes,
            context.ServerAllowedScopes,
            inheritDelegatedWhenRequestIsEmpty: true);

        if (!string.IsNullOrWhiteSpace(options.RequiredScope)
            && !context.CallerScopes.Contains(options.RequiredScope, StringComparer.Ordinal))
        {
            reasons.Add("required_scope_missing");
        }
        if (options.RequireMfa && !context.HasMfaEvidence)
        {
            reasons.Add("mfa_required");
        }
        if (options.EligibleClientIds.Count > 0
            && (string.IsNullOrWhiteSpace(context.CallerClientId)
                || !options.EligibleClientIds.Contains(context.CallerClientId)))
        {
            reasons.Add("caller_client_not_eligible");
        }

        var invalidRequestedScopes = context.RequestedScopes
            .Except(strictScopes, StringComparer.Ordinal)
            .Any();
        if (invalidRequestedScopes)
        {
            reasons.Add("requested_scope_not_delegated");
        }

        var maximumLifetime = TimeSpan.FromDays(
            Math.Clamp(options.MaximumLifetimeDays, 1, 365));
        if (context.Expiration <= context.Now
            || context.Expiration - context.Now > maximumLifetime)
        {
            reasons.Add("lifetime_exceeds_policy");
        }

        if (options.RequireRecentAuthentication)
        {
            var maximumAge = TimeSpan.FromMinutes(
                Math.Clamp(options.MaximumAuthenticationAgeMinutes, 1, 1440));
            var recent = context.AuthenticationTime is { } authenticationTime
                && authenticationTime <= context.Now + TimeSpan.FromMinutes(1)
                && context.Now - authenticationTime <= maximumAge;
            if (!recent)
            {
                reasons.Add("recent_authentication_required");
            }
        }

        if (options.RequireSenderConstraint && !context.HasSenderConstraint)
        {
            reasons.Add("sender_constraint_required");
        }

        var wouldReject = reasons.Count > 0;
        var shouldReject = wouldReject
            && options.Mode == SecurityPolicyEnforcementMode.Enforce;
        if (wouldReject)
        {
            logger.LogWarning(
                "Personal-token issuance policy {Mode} decision for subject {Subject} and caller {CallerClientId}: {ReasonCodes}.",
                options.Mode,
                context.Subject,
                context.CallerClientId ?? "<unknown>",
                string.Join(',', reasons));
        }
        telemetry?.Record(
            "personal_token_issuance",
            options.Mode.ToString(),
            wouldReject,
            shouldReject,
            reasons);

        var compatibilityScopes = context.RequestedScopes.Count > 0
            ? context.RequestedScopes
                .Intersect(context.ServerAllowedScopes, StringComparer.Ordinal)
                .Order(StringComparer.Ordinal)
                .ToArray()
            : context.ServerAllowedScopes
                .Distinct(StringComparer.Ordinal)
                .Order(StringComparer.Ordinal)
                .ToArray();
        return new PersonalTokenIssuanceDecision(
            shouldReject,
            wouldReject,
            options.Mode == SecurityPolicyEnforcementMode.Enforce
                ? strictScopes
                : compatibilityScopes,
            reasons.Contains("requested_scope_not_delegated", StringComparer.Ordinal)
                ? "invalid_scope"
                : wouldReject ? "insufficient_authorization" : null,
            reasons);
    }
}

public sealed record SubjectTokenProvenanceDecision(
    bool ShouldReject,
    bool WouldReject,
    string? AuthorizedParty,
    string? ReasonCode);

public interface ISubjectTokenProvenancePolicy
{
    /// <summary>
    /// Decides whether <paramref name="requestingClientId"/> may exchange
    /// <paramref name="subjectToken"/>.
    /// </summary>
    /// <remarks>
    /// RFC 8693 §5 requires the authorization server to establish that the
    /// client is authorized to act on behalf of the subject; being able to
    /// present the token is explicitly not sufficient, because a client that
    /// legitimately receives a token as a bearer credential could otherwise
    /// escalate it into a delegation — the confused deputy.
    /// </remarks>
    SubjectTokenProvenanceDecision Evaluate(
        ClaimsPrincipal subjectToken,
        IReadOnlySet<string> allowedSourceClientIds,
        SecurityPolicyEnforcementMode mode,
        string? requestingClientId = null);
}

internal sealed class SubjectTokenProvenancePolicy(
    ILogger<SubjectTokenProvenancePolicy> logger,
    ISecurityDecisionTelemetry? telemetry = null) : ISubjectTokenProvenancePolicy
{
    public SubjectTokenProvenanceDecision Evaluate(
        ClaimsPrincipal subjectToken,
        IReadOnlySet<string> allowedSourceClientIds,
        SecurityPolicyEnforcementMode mode,
        string? requestingClientId = null)
    {
        ArgumentNullException.ThrowIfNull(subjectToken);

        // An empty allow-list no longer short-circuits the evaluation. Whether
        // the deployment named its actor clients or not, a subject token that
        // cannot be attributed to ONE authorized party is not safe to exchange:
        // without an unambiguous azp/client_id/presenter there is nothing to
        // attribute the delegation to, which is exactly the confused-deputy
        // shape RFC 8693 §4.1 warns about. Only the membership test below is
        // conditional on an allow-list existing.
        var parties = new[]
            {
                subjectToken.GetClaim(Claims.AuthorizedParty),
                subjectToken.GetClaim(Claims.ClientId),
            }
            .Concat(subjectToken.GetPresenters())
            .Where(value => !string.IsNullOrWhiteSpace(value))
            .Distinct(StringComparer.Ordinal)
            .ToArray();
        // RFC 8693 §5 — the caller must be an INTENDED RECIPIENT of the subject
        // token, not merely its bearer. Requiring an unambiguous party (above)
        // does not establish that: OpenIddict stamps exactly one party on every
        // token it mints, so that test alone never fires and any client holding
        // the exchange grant could escalate a token it received as a bearer
        // credential into a delegation. Verified by
        // TokenExchangeConfusedDeputyTests, which reproduced exactly that.
        //
        // A caller qualifies when the token was issued TO it, or when it is a
        // declared audience/resource of the token — the two shapes in which an
        // authorization server states an intended recipient.
        var intendedRecipient =
            string.IsNullOrWhiteSpace(requestingClientId)
            || parties.Contains(requestingClientId, StringComparer.Ordinal)
            || subjectToken.GetAudiences().Contains(
                requestingClientId,
                StringComparer.Ordinal)
            || subjectToken.GetResources().Contains(
                requestingClientId,
                StringComparer.Ordinal);

        var reason = parties.Length switch
        {
            0 => "subject_authorized_party_missing",
            > 1 => "subject_authorized_party_ambiguous",
            _ when !intendedRecipient => "subject_token_audience_mismatch",
            // Membership is only meaningful when the deployment declared which
            // clients may originate a subject token. With no allow-list the
            // party is accepted, but it still had to be unambiguous above.
            _ when allowedSourceClientIds.Count > 0
                && !allowedSourceClientIds.Contains(parties[0]!) =>
                "subject_authorized_party_not_allowed",
            _ => null,
        };
        if (reason is not null)
        {
            logger.LogWarning(
                "Token-exchange subject provenance {Mode} decision: {ReasonCode}.",
                mode,
                reason);
        }

        telemetry?.Record(
            "token_exchange_provenance",
            mode.ToString(),
            reason is not null,
            reason is not null && mode == SecurityPolicyEnforcementMode.Enforce,
            reason is null ? null : [reason]);

        return new SubjectTokenProvenanceDecision(
            reason is not null && mode == SecurityPolicyEnforcementMode.Enforce,
            reason is not null,
            parties.Length == 1 ? parties[0] : null,
            reason);
    }
}
