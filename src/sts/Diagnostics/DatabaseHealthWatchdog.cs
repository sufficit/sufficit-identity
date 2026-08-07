using System.Diagnostics;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using Sufficit.Identity.Core.Data;

namespace Sufficit.Identity.STS.Diagnostics;

internal sealed class DatabaseHealthWatchdog(
    IDbContextFactory<AppDbContext> databaseFactory,
    SufficitIdentityOptions identityOptions,
    DatabaseRuntimeTelemetry telemetry,
    IHostApplicationLifetime applicationLifetime,
    ILogger<DatabaseHealthWatchdog> logger) : BackgroundService
{
    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        var options = identityOptions.Database.Watchdog;
        if (!options.Enabled)
        {
            return;
        }

        var startupDelay = Seconds(options.StartupDelaySeconds, 0, 3_600);
        var interval = Seconds(options.ProbeIntervalSeconds, 5, 3_600);
        var timeout = Seconds(options.ProbeTimeoutSeconds, 1, 300);
        var failureThreshold = Math.Clamp(
            options.ConsecutiveFailuresBeforeRestart,
            1,
            100);

        if (startupDelay > TimeSpan.Zero)
        {
            await Task.Delay(startupDelay, stoppingToken);
        }

        var consecutiveFailures = 0;
        while (!stoppingToken.IsCancellationRequested)
        {
            var stopwatch = Stopwatch.StartNew();
            var healthy = false;
            string? failureCode = null;
            try
            {
                using var timeoutCancellation =
                    CancellationTokenSource.CreateLinkedTokenSource(stoppingToken);
                timeoutCancellation.CancelAfter(timeout);
                await using var database =
                    await databaseFactory.CreateDbContextAsync(
                        timeoutCancellation.Token);
                healthy = await database.Database.CanConnectAsync(
                    timeoutCancellation.Token);
                if (!healthy)
                {
                    failureCode = "database_unreachable";
                }
            }
            catch (OperationCanceledException) when (stoppingToken.IsCancellationRequested)
            {
                return;
            }
            catch (OperationCanceledException exception)
            {
                failureCode = "database_probe_timeout";
                logger.LogWarning(
                    exception,
                    "Database watchdog probe timed out after {TimeoutSeconds} seconds.",
                    timeout.TotalSeconds);
            }
            catch (Exception exception)
            {
                failureCode = "database_probe_failed";
                logger.LogWarning(
                    exception,
                    "Database watchdog probe failed.");
            }
            finally
            {
                stopwatch.Stop();
            }

            consecutiveFailures = healthy ? 0 : consecutiveFailures + 1;
            telemetry.RecordWatchdogProbe(
                healthy,
                consecutiveFailures,
                stopwatch.Elapsed,
                failureCode);

            if (!healthy && consecutiveFailures >= failureThreshold)
            {
                telemetry.RecordWatchdogStopping(consecutiveFailures);
                logger.LogCritical(
                    "Database watchdog reached {FailureCount} consecutive failures. Stopping the process with exit code 1 so the supervisor can recreate the connection pools.",
                    consecutiveFailures);
                Environment.ExitCode = 1;
                applicationLifetime.StopApplication();
                return;
            }

            await Task.Delay(interval, stoppingToken);
        }
    }

    private static TimeSpan Seconds(int value, int minimum, int maximum) =>
        TimeSpan.FromSeconds(Math.Clamp(value, minimum, maximum));
}
