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
    ILogger<ApplicationClaimDestinationPolicy>? logger = null) : IApplicationClaimDestinationPolicy
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
    bool HasSenderConstraint);

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
    ILogger<PersonalTokenIssuancePolicy> logger) : IPersonalTokenIssuancePolicy
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
    SubjectTokenProvenanceDecision Evaluate(
        ClaimsPrincipal subjectToken,
        IReadOnlySet<string> allowedSourceClientIds,
        SecurityPolicyEnforcementMode mode);
}

internal sealed class SubjectTokenProvenancePolicy(
    ILogger<SubjectTokenProvenancePolicy> logger) : ISubjectTokenProvenancePolicy
{
    public SubjectTokenProvenanceDecision Evaluate(
        ClaimsPrincipal subjectToken,
        IReadOnlySet<string> allowedSourceClientIds,
        SecurityPolicyEnforcementMode mode)
    {
        ArgumentNullException.ThrowIfNull(subjectToken);
        if (allowedSourceClientIds.Count == 0)
        {
            return new SubjectTokenProvenanceDecision(false, false, null, null);
        }

        var parties = new[]
            {
                subjectToken.GetClaim(Claims.AuthorizedParty),
                subjectToken.GetClaim(Claims.ClientId),
            }
            .Concat(subjectToken.GetPresenters())
            .Where(value => !string.IsNullOrWhiteSpace(value))
            .Distinct(StringComparer.Ordinal)
            .ToArray();
        var reason = parties.Length switch
        {
            0 => "subject_authorized_party_missing",
            > 1 => "subject_authorized_party_ambiguous",
            _ when !allowedSourceClientIds.Contains(parties[0]!) =>
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

        return new SubjectTokenProvenanceDecision(
            reason is not null && mode == SecurityPolicyEnforcementMode.Enforce,
            reason is not null,
            parties.Length == 1 ? parties[0] : null,
            reason);
    }
}
