using System.Globalization;
using System.Security.Claims;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.Logging;
using Sufficit.Identity.Application.Security;
using Sufficit.Identity.Core.Entities;
using Sufficit.Identity.Core.Services;

namespace Sufficit.Identity.STS;

public enum CredentialMutationStepUpMode
{
    Audit,
    Enforce,
}

public sealed class CredentialMutationSecurityOptions
{
    public CredentialMutationStepUpMode StepUpMode { get; init; } =
        CredentialMutationStepUpMode.Audit;

    public int MaximumAuthenticationAgeMinutes { get; init; } = 15;
}

public sealed record CredentialMutationAuthorization(
    bool Allowed,
    string? ErrorCode = null,
    string? ErrorDescription = null);

public interface ICredentialMutationSecurityCoordinator
{
    Task<CredentialMutationAuthorization> AuthorizeAsync(
        ClaimsPrincipal principal,
        string operation,
        bool independentProofSatisfied = false,
        CancellationToken cancellationToken = default);

    Task<IdentityUserSessionRevocation> CompleteAsync(
        ApplicationUser user,
        ClaimsPrincipal principal,
        CaepCredentialChange change,
        CancellationToken cancellationToken = default);
}

public sealed class CredentialMutationSecurityCoordinator(
    UserManager<ApplicationUser> userManager,
    SignInManager<ApplicationUser> signInManager,
    IIdentityUserSessionRevoker sessionRevoker,
    ISecurityEventTrigger securityEvents,
    IHttpContextAccessor httpContextAccessor,
    CredentialMutationSecurityOptions options,
    TimeProvider timeProvider,
    ILogger<CredentialMutationSecurityCoordinator> logger)
    : ICredentialMutationSecurityCoordinator
{
    private const string SessionIdClaimType = "sid";
    private const string AuthenticationTimeClaimType = "auth_time";

    public async Task<CredentialMutationAuthorization> AuthorizeAsync(
        ClaimsPrincipal principal,
        string operation,
        bool independentProofSatisfied = false,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(principal);
        ArgumentException.ThrowIfNullOrWhiteSpace(operation);
        if (independentProofSatisfied)
        {
            return new CredentialMutationAuthorization(true);
        }

        var authenticatedAt = await ResolveAuthenticationTimeAsync(
            principal,
            cancellationToken);
        var maximumAge = TimeSpan.FromMinutes(
            Math.Clamp(options.MaximumAuthenticationAgeMinutes, 1, 1440));
        var now = timeProvider.GetUtcNow();
        var recent = authenticatedAt is { } value
            && value <= now + TimeSpan.FromMinutes(1)
            && now - value <= maximumAge;
        if (recent)
        {
            return new CredentialMutationAuthorization(true);
        }

        if (options.StepUpMode == CredentialMutationStepUpMode.Enforce)
        {
            logger.LogWarning(
                "Credential mutation {Operation} was rejected because the authenticated session is not recent enough.",
                operation);
            return new CredentialMutationAuthorization(
                false,
                "step-up-required",
                "Confirme sua identidade entrando novamente antes de alterar credenciais de acesso.");
        }

        logger.LogWarning(
            "Credential mutation {Operation} would require step-up in Enforce mode; Audit mode preserved the current production flow.",
            operation);
        return new CredentialMutationAuthorization(true);
    }

    public async Task<IdentityUserSessionRevocation> CompleteAsync(
        ApplicationUser user,
        ClaimsPrincipal principal,
        CaepCredentialChange change,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(user);
        ArgumentNullException.ThrowIfNull(principal);

        var stamp = await userManager.UpdateSecurityStampAsync(user);
        if (!stamp.Succeeded)
        {
            throw new IdentityAccountLifecycleException(stamp);
        }

        var currentSessionId = principal.FindFirst(SessionIdClaimType)?.Value;
        var revocation = await sessionRevoker.RevokeAsync(
            user.Id,
            currentSessionId,
            cancellationToken);

        if (httpContextAccessor.HttpContext is not null)
        {
            await signInManager.RefreshSignInAsync(user);
        }

        await securityEvents.CredentialChangedAsync(
            principal,
            user.Id,
            change,
            cancellationToken);

        logger.LogInformation(
            "Credential mutation for user {UserId} revoked {TokenCount} tokens, {AuthorizationCount} authorizations and {BrowserSessionCount} other browser sessions.",
            user.Id,
            revocation.RevokedTokens,
            revocation.RevokedAuthorizations,
            revocation.RevokedBrowserSessions);
        return revocation;
    }

    private async Task<DateTimeOffset?> ResolveAuthenticationTimeAsync(
        ClaimsPrincipal principal,
        CancellationToken cancellationToken)
    {
        var claim = principal.FindFirst(AuthenticationTimeClaimType)?.Value;
        if (long.TryParse(
                claim,
                NumberStyles.Integer,
                CultureInfo.InvariantCulture,
                out var unixSeconds))
        {
            try
            {
                return DateTimeOffset.FromUnixTimeSeconds(unixSeconds);
            }
            catch (ArgumentOutOfRangeException)
            {
                return null;
            }
        }

        var context = httpContextAccessor.HttpContext;
        if (context is null)
        {
            return null;
        }

        var ticket = await context.AuthenticateAsync(
            IdentityConstants.ApplicationScheme);
        cancellationToken.ThrowIfCancellationRequested();
        return ticket.Succeeded ? ticket.Properties?.IssuedUtc : null;
    }
}
