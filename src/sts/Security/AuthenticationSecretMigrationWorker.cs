using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using Sufficit.Identity.Core.Data;
using Sufficit.Identity.Vault;

namespace Sufficit.Identity.STS.Security;

/// <summary>
/// Encrypts the authenticator keys and recovery codes still stored as plain
/// text (plan C3), in small batches, then re-checks every hour. Nobody's MFA is
/// reset: each value is encrypted as it is.
/// </summary>
/// <remarks>
/// Every node runs it. The update is conditional on the value it read, so two
/// nodes on the same row, or a user changing it meanwhile, never lose a write.
/// The remaining count is logged on every pass: zero is the signal to turn
/// <c>TwoFactor:AcceptPlaintextSecrets</c> off.
/// </remarks>
internal sealed class AuthenticationSecretMigrationWorker(
    IDbContextFactory<AppDbContext> databaseFactory,
    IKeyVault vault,
    ILogger<AuthenticationSecretMigrationWorker> logger) : BackgroundService
{
    internal const int BatchSize = 100;
    // Longer than a rolling deploy: a node still on a build without this store
    // would read an encrypted value as if it were the plain key.
    private static readonly TimeSpan StartDelay = TimeSpan.FromMinutes(10);
    private static readonly TimeSpan Interval = TimeSpan.FromHours(1);

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        try
        {
            await Task.Delay(StartDelay, stoppingToken);
            while (!stoppingToken.IsCancellationRequested)
            {
                try
                {
                    await MigrateAsync(stoppingToken);
                }
                catch (Exception exception) when (!stoppingToken.IsCancellationRequested)
                {
                    logger.LogWarning(exception, "Authentication secrets migration pass failed; retrying in an hour.");
                }
                await Task.Delay(Interval, stoppingToken);
            }
        }
        catch (OperationCanceledException) when (stoppingToken.IsCancellationRequested)
        {
        }
    }

    /// <summary>One full pass. Returns how many values it encrypted and how many plain-text values remain.</summary>
    internal async Task<(int Encrypted, int Remaining)> MigrateAsync(CancellationToken cancellationToken)
    {
        var encrypted = 0;
        while (true)
        {
            await using var database = await databaseFactory.CreateDbContextAsync(cancellationToken);
            var batch = await Plaintext(database)
                .OrderBy(token => token.UserId).ThenBy(token => token.Name)
                .Take(BatchSize)
                .ToListAsync(cancellationToken);
            if (batch.Count == 0) break;

            var progressed = 0;
            foreach (var token in batch)
            {
                var ciphertext = await AuthenticationSecretProtection.EncryptAsync(
                    vault, token.UserId, token.LoginProvider, token.Name, token.Value!, cancellationToken);
                var plaintext = token.Value;
                progressed += await database.UserTokens
                    .Where(row => row.UserId == token.UserId && row.LoginProvider == token.LoginProvider
                        && row.Name == token.Name && row.Value == plaintext)
                    .ExecuteUpdateAsync(set => set.SetProperty(row => row.Value, ciphertext), cancellationToken);
            }
            encrypted += progressed;
            // Nothing of this batch changed here (another node got there first, or
            // the rows keep changing): stop; the next pass picks up what is left.
            if (progressed == 0) break;
        }

        await using var count = await databaseFactory.CreateDbContextAsync(cancellationToken);
        var remaining = await Plaintext(count).CountAsync(cancellationToken);
        logger.LogInformation(
            "Authentication secrets: {Encrypted} encrypted in this pass, {Remaining} still in plain text.",
            encrypted, remaining);
        return (encrypted, remaining);
    }

    private static IQueryable<Microsoft.AspNetCore.Identity.IdentityUserToken<string>> Plaintext(AppDbContext database) =>
        database.UserTokens.AsNoTracking().Where(token =>
            token.LoginProvider == AuthenticationSecretProtection.Provider
            && (token.Name == AuthenticationSecretProtection.AuthenticatorKey
                || token.Name == AuthenticationSecretProtection.RecoveryCodes)
            && token.Value != null
            && !token.Value.StartsWith("v1.")
            && !token.Value.StartsWith("pt1."));
}
