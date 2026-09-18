using System.Globalization;
using System.Security.Claims;
using Sufficit.Identity.Core.Sessions;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Sufficit.Identity.Core.Entities;

namespace Sufficit.Identity.STS;

/// <summary>
/// Security-stamp validator for the application cookie that separates the
/// revocation check from the principal refresh.
/// </summary>
/// <remarks>
/// <para>
/// The framework validator couples both concerns to one interval. With the
/// interval at zero, which prompt revocation requires, every cookie-authenticated
/// request rebuilds the principal through the claims factory and renews the
/// server-side ticket, costing several queries and a write per request.
/// </para>
/// <para>
/// This validator still compares the security stamp on every request (a single
/// primary-key read), so a stamp rotation rejects the session immediately. The
/// principal is rebuilt and the ticket renewed only when the refresh interval
/// has elapsed or the user row changed since the last refresh. Every
/// <see cref="UserManager{TUser}"/> mutation, including role, claim and
/// lockout changes that do not rotate the stamp, rotates the row's
/// <see cref="IdentityUser{TKey}.ConcurrencyStamp"/>; the last observed value
/// is kept in the server-side ticket properties, never in the principal, so
/// it cannot reach a token.
/// </para>
/// </remarks>
public sealed class SessionSecurityStampValidator : SecurityStampValidator<ApplicationUser>
{
    /// <summary>
    /// Ticket property holding the user row version observed at the last
    /// principal refresh.
    /// </summary>
    public const string UserVersionItem = ".identity.user_version";

    /// <summary>
    /// Ticket property holding the moment the user row was last read and
    /// accepted for this session.
    /// </summary>
    public const string VerifiedAtItem = ".identity.verified_at";

    private readonly TimeSpan _refreshInterval;
    private readonly ISessionValidityCache? _validityCache;
    private readonly IUserSecurityChangePublisher? _changePublisher;

    public SessionSecurityStampValidator(
        IOptions<SecurityStampValidatorOptions> options,
        SignInManager<ApplicationUser> signInManager,
        ILoggerFactory logger,
        SufficitIdentityOptions identityOptions,
        ISessionValidityCache? validityCache = null,
        IUserSecurityChangePublisher? changePublisher = null)
        : base(options, signInManager, logger)
    {
        _refreshInterval = TimeSpan.FromSeconds(Math.Clamp(
            identityOptions.UserSessions.PrincipalRefreshIntervalSeconds,
            0,
            3600));
        _validityCache = validityCache;
        _changePublisher = changePublisher;
    }

    public override async Task ValidateAsync(CookieValidatePrincipalContext context)
    {
        var issuedUtc = context.Properties.IssuedUtc;
        if (issuedUtc is null ||
            TimeProvider.GetUtcNow() - issuedUtc.Value >= _refreshInterval)
        {
            await base.ValidateAsync(context);
            return;
        }

        // The stamp read is one primary-key lookup, but it happens on every
        // request of every signed-in user. It can be skipped only while a
        // change notification channel is connected: without one, this node
        // would not hear about a revocation performed on another node.
        if (CanTrustWithoutReading(context))
        {
            return;
        }

        var user = await VerifySecurityStamp(context.Principal);
        if (user is not null &&
            context.Properties.Items.TryGetValue(UserVersionItem, out var version) &&
            string.Equals(version, user.ConcurrencyStamp, StringComparison.Ordinal))
        {
            RecordVerification(context, user);
            return;
        }

        // Rejected stamp or changed user row: the framework path verifies
        // again (the user is already tracked by the scope) and either rejects
        // and signs out, or rebuilds the principal and renews the ticket.
        await base.ValidateAsync(context);
    }

    protected override async Task SecurityStampVerified(
        ApplicationUser user,
        CookieValidatePrincipalContext context)
    {
        await base.SecurityStampVerified(user, context);
        context.Properties.Items[UserVersionItem] = user.ConcurrencyStamp;
        RecordVerification(context, user);
    }

    /// <summary>
    /// Whether this request may accept the ticket without reading the user
    /// row, because the row was read recently enough and nothing has
    /// invalidated the user since.
    /// </summary>
    private bool CanTrustWithoutReading(CookieValidatePrincipalContext context)
    {
        if (_validityCache is null || _changePublisher?.Connected is not true)
        {
            return false;
        }

        if (context.Principal?.FindFirst(ClaimTypes.NameIdentifier)?.Value
            is not { Length: > 0 } userId)
        {
            return false;
        }

        if (!context.Properties.Items.TryGetValue(VerifiedAtItem, out var value)
            || !DateTimeOffset.TryParse(
                value,
                CultureInfo.InvariantCulture,
                DateTimeStyles.RoundtripKind,
                out var verifiedAt))
        {
            return false;
        }

        return !_validityCache.IsRevalidationNeeded(userId, verifiedAt);
    }

    private void RecordVerification(
        CookieValidatePrincipalContext context,
        ApplicationUser user)
    {
        if (_validityCache is null)
        {
            return;
        }

        context.Properties.Items[VerifiedAtItem] = TimeProvider
            .GetUtcNow()
            .ToString("O", CultureInfo.InvariantCulture);
        _validityCache.MarkVerified(user.Id);
    }
}
