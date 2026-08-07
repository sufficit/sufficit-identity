using System.Globalization;
using System.Security.Claims;
using System.Collections.Immutable;
using OpenIddict.Abstractions;

namespace Sufficit.Identity.STS;

public sealed record AuthenticationContextEvidence(
    IReadOnlyCollection<string> AuthenticationMethods,
    DateTimeOffset AuthenticatedAt,
    string AuthenticationContextClass);

public interface IAuthenticationContextAccessor
{
    AuthenticationContextEvidence? Current { get; }

    void Set(AuthenticationContextEvidence evidence);
}

internal sealed class AuthenticationContextAccessor : IAuthenticationContextAccessor
{
    public AuthenticationContextEvidence? Current { get; private set; }

    public void Set(AuthenticationContextEvidence evidence) =>
        Current = evidence ?? throw new ArgumentNullException(nameof(evidence));
}

public interface IAuthenticationContextProjector
{
    void Project(ClaimsPrincipal source, ClaimsIdentity destination);
}

internal sealed class AuthenticationContextProjector : IAuthenticationContextProjector
{
    public const string AuthenticationMethodClaimType = "amr";
    public const string AuthenticationContextClassClaimType = "acr";
    public const string AuthenticationTimeClaimType = "auth_time";

    public void Project(ClaimsPrincipal source, ClaimsIdentity destination)
    {
        ArgumentNullException.ThrowIfNull(source);
        ArgumentNullException.ThrowIfNull(destination);

        var methods = source.FindAll(AuthenticationMethodClaimType)
            .SelectMany(claim => SplitValues(claim.Value))
            .Distinct(StringComparer.Ordinal)
            .ToArray();
        destination.SetClaims(
            AuthenticationMethodClaimType,
            methods.ToImmutableArray());

        var authenticationTime = source.FindFirst(AuthenticationTimeClaimType)?.Value;
        if (long.TryParse(
                authenticationTime,
                NumberStyles.Integer,
                CultureInfo.InvariantCulture,
                out var unixSeconds))
        {
            destination.SetClaim(AuthenticationTimeClaimType, unixSeconds);
        }

        var authenticationContext = source.FindFirst(
            AuthenticationContextClassClaimType)?.Value;
        if (string.IsNullOrWhiteSpace(authenticationContext))
        {
            var assuranceLevel = source.FindFirst(
                OidcSessionClaimsPrincipalFactory.AssuranceLevelClaimType)?.Value;
            if (!string.IsNullOrWhiteSpace(assuranceLevel))
                authenticationContext = "urn:sufficit:acr:loa" + assuranceLevel;
        }
        if (!string.IsNullOrWhiteSpace(authenticationContext))
            destination.SetClaim(
                AuthenticationContextClassClaimType,
                authenticationContext);
    }

    private static IEnumerable<string> SplitValues(string value) =>
        value.Split(' ', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);
}
