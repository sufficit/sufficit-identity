using System.Security.Claims;
using System.Security.Cryptography;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.WebUtilities;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Microsoft.EntityFrameworkCore;
using Sufficit.Identity.Core.Data;
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
    IDbContextFactory<AppDbContext> databaseFactory,
    TimeProvider timeProvider,
    ILogger<OidcSessionClaimsPrincipalFactory> logger)
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

        // RefreshSignInAsync replaces the cookie principal. Reuse the current
        // session's sid when present so account edits/security-stamp renewal do
        // not look like a brand-new OP session to relying parties.
        var currentPrincipal = httpContextAccessor.HttpContext?.User;
        var currentSubject = currentPrincipal?.FindFirst(
                ClaimTypes.NameIdentifier)?.Value
            ?? currentPrincipal?.FindFirst("sub")?.Value;
        // A sid copied from user claims is not session evidence: claims can be
        // stale, imported, or deliberately supplied by a caller. Reuse is
        // allowed only when the current principal is the same subject AND a
        // durable session row proves that sid belongs to that subject.
        var sessionId = string.Equals(
                currentSubject,
                user.Id,
                StringComparison.Ordinal)
            ? currentPrincipal?.FindFirst(SessionIdClaimType)?.Value
            : null;
        if (!string.IsNullOrWhiteSpace(sessionId))
        {
            await using var database = await databaseFactory.CreateDbContextAsync();
            var persisted = await database.OidcUserSessions
                .AsNoTracking()
                .AnyAsync(
                    session => session.SessionId == sessionId &&
                        session.Subject == user.Id);
            if (!persisted)
            {
                sessionId = null;
            }
        }

        if (string.IsNullOrWhiteSpace(sessionId))
        {
            sessionId = WebEncoders.Base64UrlEncode(
                RandomNumberGenerator.GetBytes(32));
        }

        ReplaceClaim(identity, SessionIdClaimType, sessionId);

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
            if (!identity.HasClaim(
                AuthenticationContextProjector.AuthenticationMethodClaimType,
                method))
            {
                identity.AddClaim(new Claim(
                    AuthenticationContextProjector.AuthenticationMethodClaimType,
                    method));
            }
        }
        var authenticatedAt = evidence?.AuthenticatedAt
            ?? ResolveAuthenticationTime(currentPrincipal)
            ?? timeProvider.GetUtcNow();
        ReplaceClaim(
            identity,
            AuthenticationContextProjector.AuthenticationTimeClaimType,
            authenticatedAt.ToUnixTimeSeconds().ToString(
                System.Globalization.CultureInfo.InvariantCulture));

        // Stamp the authentication assurance level (aal) on the session so the
        // CAEP assurance-level-change trigger can read the previous level off
        // the pre-step-up cookie before it is replaced. Derived from the amr
        // claims of the in-flight principal (sign-in flow); missing amr → the
        // resolver returns Loa1, the safe floor.
        var aal = assuranceLevelResolver.Resolve(new ClaimsPrincipal(identity));
        ReplaceClaim(identity, AssuranceLevelClaimType, aal.ToString());
        ReplaceClaim(
            identity,
            AuthenticationContextProjector.AuthenticationContextClassClaimType,
            evidence?.AuthenticationContextClass ?? "urn:sufficit:acr:loa" + aal);

        logger.LogInformation(
            "Session claims projected for user {UserId}: amr={AuthenticationMethods}; "
            + "aal={AssuranceLevel}; acr={AuthenticationContextClass}.",
            user.Id,
            string.Join(' ', authenticationMethods),
            aal,
            identity.FindFirst(
                AuthenticationContextProjector.AuthenticationContextClassClaimType)?.Value
                ?? "missing");

        return identity;
    }

    private static void ReplaceClaim(
        ClaimsIdentity identity,
        string claimType,
        string value)
    {
        foreach (var existing in identity.FindAll(claimType).ToArray())
        {
            identity.RemoveClaim(existing);
        }

        identity.AddClaim(new Claim(claimType, value));
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
