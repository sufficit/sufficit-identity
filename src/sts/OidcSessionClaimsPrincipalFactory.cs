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
    IHttpContextAccessor httpContextAccessor)
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
        var sessionId = httpContextAccessor.HttpContext?.User
            .FindFirst(SessionIdClaimType)?.Value;
        if (string.IsNullOrWhiteSpace(sessionId))
        {
            sessionId = WebEncoders.Base64UrlEncode(
                RandomNumberGenerator.GetBytes(32));
        }

        identity.AddClaim(new Claim(SessionIdClaimType, sessionId));

        // Stamp the authentication assurance level (aal) on the session so the
        // CAEP assurance-level-change trigger can read the previous level off
        // the pre-step-up cookie before it is replaced. Derived from the amr
        // claims of the in-flight principal (sign-in flow); missing amr → the
        // resolver returns Loa1, the safe floor.
        var aal = assuranceLevelResolver.Resolve(
            httpContextAccessor.HttpContext?.User ?? new ClaimsPrincipal());
        identity.AddClaim(new Claim(
            AssuranceLevelClaimType,
            aal.ToString()));

        return identity;
    }
}
