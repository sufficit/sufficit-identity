using System.Security.Claims;
using System.Security.Cryptography;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.WebUtilities;
using Microsoft.Extensions.Options;
using Sufficit.Identity.Core.Entities;

namespace Sufficit.Identity.STS;

/// <summary>
/// Adds the stable opaque OIDC <c>sid</c> to the ASP.NET Identity application
/// cookie. The claim is provider-neutral and later projected into ID Tokens by
/// the STS protocol adapter.
/// </summary>
internal sealed class OidcSessionClaimsPrincipalFactory(
    UserManager<ApplicationUser> userManager,
    RoleManager<ApplicationRole> roleManager,
    IOptions<IdentityOptions> identityOptions,
    IAssuranceLevelResolver assuranceLevelResolver,
    IHttpContextAccessor httpContextAccessor,
    IAuthenticationContextAccessor authenticationContextAccessor,
    TimeProvider timeProvider)
    : UserClaimsPrincipalFactory<ApplicationUser, ApplicationRole>(
        userManager,
        roleManager,
        identityOptions)
{
    internal const string SessionIdClaimType = "sid";
    internal const string AssuranceLevelClaimType = "aal";

    protected override async Task<ClaimsIdentity> GenerateClaimsAsync(
        ApplicationUser user)
    {
        var identity = await base.GenerateClaimsAsync(user);
        if (identity.HasClaim(claim => claim.Type == SessionIdClaimType))
        {
            return identity;
        }

        // RefreshSignInAsync replaces the cookie principal. Reuse the current
        // session's sid when present so account edits/security-stamp renewal do
        // not look like a brand-new OP session to relying parties.
        var currentPrincipal = httpContextAccessor.HttpContext?.User;
        var currentSubject = currentPrincipal?.FindFirst(
                ClaimTypes.NameIdentifier)?.Value
            ?? currentPrincipal?.FindFirst("sub")?.Value;
        var sessionId = string.Equals(currentSubject, user.Id, StringComparison.Ordinal)
            ? currentPrincipal?.FindFirst(SessionIdClaimType)?.Value
            : null;
        if (string.IsNullOrWhiteSpace(sessionId))
        {
            sessionId = WebEncoders.Base64UrlEncode(
                RandomNumberGenerator.GetBytes(32));
        }

        identity.AddClaim(new Claim(SessionIdClaimType, sessionId));

        var evidence = authenticationContextAccessor.Current;
        var authenticationMethods = evidence?.AuthenticationMethods
            ?? currentPrincipal?.FindAll(AuthenticationContextProjector.AuthenticationMethodClaimType)
                .SelectMany(claim => claim.Value.Split(
                    ' ',
                    StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries))
                .Distinct(StringComparer.Ordinal)
                .ToArray()
            ?? [];
        foreach (var method in authenticationMethods)
        {
            identity.AddClaim(new Claim(
                AuthenticationContextProjector.AuthenticationMethodClaimType,
                method));
        }
        var authenticatedAt = evidence?.AuthenticatedAt
            ?? ResolveAuthenticationTime(currentPrincipal)
            ?? timeProvider.GetUtcNow();
        identity.AddClaim(new Claim(
            AuthenticationContextProjector.AuthenticationTimeClaimType,
            authenticatedAt.ToUnixTimeSeconds().ToString(
                System.Globalization.CultureInfo.InvariantCulture)));

        // Stamp the authentication assurance level (aal) on the session so the
        // CAEP assurance-level-change trigger can read the previous level off
        // the pre-step-up cookie before it is replaced. Derived from the amr
        // claims of the in-flight principal (sign-in flow); missing amr → the
        // resolver returns Loa1, the safe floor.
        var aal = assuranceLevelResolver.Resolve(new ClaimsPrincipal(identity));
        identity.AddClaim(new Claim(
            AssuranceLevelClaimType,
            aal.ToString()));
        identity.AddClaim(new Claim(
            AuthenticationContextProjector.AuthenticationContextClassClaimType,
            evidence?.AuthenticationContextClass ?? "urn:sufficit:acr:loa" + aal));

        return identity;
    }

    private static DateTimeOffset? ResolveAuthenticationTime(ClaimsPrincipal? principal)
    {
        var value = principal?.FindFirst(
            AuthenticationContextProjector.AuthenticationTimeClaimType)?.Value;
        return long.TryParse(value, out var unixSeconds)
            ? DateTimeOffset.FromUnixTimeSeconds(unixSeconds)
            : null;
    }
}
