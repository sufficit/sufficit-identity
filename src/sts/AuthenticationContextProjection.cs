using Sufficit.Identity.Application.Security;
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

internal sealed class AuthenticationContextProjector(
    IAuthenticationContextClassMapper authenticationContextClasses)
    : IAuthenticationContextProjector
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
            // The session stamps the level by enum name (for example "Loa2");
            // spell it through the mapper instead of concatenating the name.
            var assuranceLevel = source.FindFirst(
                OidcSessionClaimsPrincipalFactory.AssuranceLevelClaimType)?.Value;
            if (Enum.TryParse<CaepAssuranceLevel>(
                    assuranceLevel,
                    ignoreCase: false,
                    out var level))
                authenticationContext = authenticationContextClasses.Map(level);
        }
        if (!string.IsNullOrWhiteSpace(authenticationContext))
            destination.SetClaim(
                AuthenticationContextClassClaimType,
                authenticationContext);
    }

    private static IEnumerable<string> SplitValues(string value) =>
        value.Split(' ', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);
}
