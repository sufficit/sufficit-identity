using System.Text.Json;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using OpenIddict.EntityFrameworkCore.Models;
using Sufficit.Identity.Core.Data;
using Sufficit.Identity.Core.Entities;
using Sufficit.Identity.Management.Authorization;

namespace Sufficit.Identity.Management.Users;

/// <summary>
/// Deletes accounts whose email was never confirmed and that showed no sign of
/// use for <see cref="ManagementOptions.UnconfirmedAccountPurgeDays"/>. With
/// <c>RequireConfirmedEmail</c> on, such an account cannot sign in; it is a
/// registration that was abandoned, and keeping it only keeps personal data.
/// </summary>
/// <remarks>
/// Every replica runs it. Deletion goes through <see cref="UserManager{TUser}"/>,
/// which checks the row's concurrency stamp: when two replicas pick the same
/// account one deletes it and the other skips it, and only the one that deleted
/// writes the audit event.
/// </remarks>
internal sealed class UnconfirmedAccountPurgeWorker(
    IServiceScopeFactory scopes,
    IOptions<ManagementOptions> optionsAccessor,
    ILogger<UnconfirmedAccountPurgeWorker> logger) : BackgroundService
{
    internal const string Operator = "system:unconfirmed-account-purge";
    internal const string ReasonCode = "unconfirmed_account_purged";
    private static readonly TimeSpan Interval = TimeSpan.FromHours(24);
    private const int MaximumPerPass = 200;

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        try
        {
            // Replicas started together would otherwise all scan at once.
            await Task.Delay(TimeSpan.FromMinutes(5 + Random.Shared.Next(0, 30)), stoppingToken);
            while (!stoppingToken.IsCancellationRequested)
            {
                try
                {
                    await PurgeAsync(stoppingToken);
                }
                catch (Exception error) when (!stoppingToken.IsCancellationRequested)
                {
                    logger.LogWarning(error, "Unconfirmed account purge failed; retrying in a day.");
                }
                await Task.Delay(Interval, stoppingToken);
            }
        }
        catch (OperationCanceledException) when (stoppingToken.IsCancellationRequested)
        {
        }
    }

    /// <summary>One pass; returns how many accounts it deleted.</summary>
    internal async Task<int> PurgeAsync(CancellationToken cancellationToken)
    {
        var days = optionsAccessor.Value.UnconfirmedAccountPurgeDays;
        if (days <= 0) return 0;
        var cutoff = DateTime.UtcNow.AddDays(-Math.Max(30, days));

        await using var scope = scopes.CreateAsyncScope();
        var database = scope.ServiceProvider.GetRequiredService<AppDbContext>();
        var users = scope.ServiceProvider.GetRequiredService<UserManager<ApplicationUser>>();
        var candidates = await Eligible(database, cutoff).Take(MaximumPerPass).ToListAsync(cancellationToken);

        var deleted = 0;
        foreach (var id in candidates)
        {
            var user = await users.FindByIdAsync(id);
            // Re-checked on the tracked row; a lockout in the window is a sign
            // of sign-in attempts (compared here: SQLite cannot translate it).
            if (user is null || user.EmailConfirmed || string.IsNullOrEmpty(user.Email)
                || user.LockoutEnd > new DateTimeOffset(cutoff, TimeSpan.Zero)) continue;
            IdentityResult result;
            try
            {
                result = await users.DeleteAsync(user);
            }
            catch (DbUpdateConcurrencyException)
            {
                continue; // Another replica got there first.
            }
            if (!result.Succeeded) continue;

            database.ManagementAuditEvents.Add(new ManagementAuditEvent
            {
                OccurredAtUtc = DateTime.UtcNow,
                OperatorSubject = Operator,
                Capability = ManagementCapabilities.UsersDelete,
                ResourceType = ManagementResourceTypes.User,
                ResourceId = id,
                AuthorizationOutcome = "allowed",
                OperationOutcome = "succeeded",
                ReasonCode = ReasonCode,
                CorrelationId = Guid.NewGuid().ToString("N"),
                // No email or name: the point of deleting is not keeping them.
                AfterJson = JsonSerializer.Serialize(new { Deleted = true, InactiveDays = days, user.CreatedAtUtc }),
                ExpiresAtUtc = DateTime.UtcNow.AddDays(365),
            });
            await database.SaveChangesAsync(cancellationToken);
            deleted++;
        }

        if (deleted > 0 || candidates.Count > 0)
            logger.LogInformation("Unconfirmed account purge: {Deleted} of {Candidates} candidate(s) deleted (inactive {Days} days).",
                deleted, candidates.Count, days);
        return deleted;
    }

    /// <summary>
    /// Unconfirmed, with an email, older than the cutoff and holding nothing:
    /// no external login, claim or role; in the window no token, authorization,
    /// session, failed sign-in, lockout or recorded usage.
    /// </summary>
    internal static IQueryable<string> Eligible(AppDbContext database, DateTime cutoff)
    {
        return database.Users.AsNoTracking()
            .Where(user => !user.EmailConfirmed && user.Email != null && user.Email != ""
                && user.CreatedAtUtc < cutoff
                && user.AccessFailedCount == 0
                && !database.UserLogins.Any(login => login.UserId == user.Id)
                && !database.UserClaims.Any(claim => claim.UserId == user.Id)
                && !database.UserRoles.Any(role => role.UserId == user.Id)
                && !database.Set<OpenIddictEntityFrameworkCoreToken>().Any(token =>
                    token.Subject == user.Id && token.CreationDate > cutoff)
                && !database.Set<OpenIddictEntityFrameworkCoreAuthorization>().Any(authorization =>
                    authorization.Subject == user.Id && authorization.CreationDate > cutoff)
                && !database.OidcUserSessions.Any(session => session.Subject == user.Id)
                && !database.IdentityApplicationUsageDaily.Any(usage =>
                    usage.UserId == user.Id && usage.Day > cutoff))
            .OrderBy(user => user.CreatedAtUtc)
            .Select(user => user.Id);
    }
}
