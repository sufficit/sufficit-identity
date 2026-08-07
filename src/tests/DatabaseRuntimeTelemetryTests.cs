using Microsoft.Data.Sqlite;
using MySqlConnector;
using Sufficit.Identity.STS;
using Sufficit.Identity.STS.Diagnostics;
using Xunit;

namespace Sufficit.Identity.Tests;

public sealed class DatabaseRuntimeTelemetryTests
{
    [Fact]
    public void Connection_policy_applies_bounded_resilient_defaults()
    {
        const string configured =
            "Server=db.internal;Database=identity;User ID=identity;Password=secret";
        var policy = new DatabaseConnectionPoolOptions
        {
            MaximumSize = 42,
            MinimumSize = 2,
            ConnectionTimeoutSeconds = 12,
            CommandTimeoutSeconds = 28,
            ConnectionLifetimeSeconds = 240,
            ConnectionIdleTimeoutSeconds = 90,
            ResetOnCheckout = true,
            ApplicationName = "Sufficit.Identity.Tests"
        };

        var effective =
            Sufficit.Identity.STS.ServiceCollectionExtensions
                .ApplyDatabaseConnectionPolicy(configured, policy);
        var builder = new MySqlConnectionStringBuilder(effective);

        Assert.True(builder.Pooling);
        Assert.Equal((uint)42, builder.MaximumPoolSize);
        Assert.Equal((uint)2, builder.MinimumPoolSize);
        Assert.Equal((uint)12, builder.ConnectionTimeout);
        Assert.Equal((uint)28, builder.DefaultCommandTimeout);
        Assert.Equal((uint)240, builder.ConnectionLifeTime);
        Assert.Equal((uint)90, builder.ConnectionIdleTimeout);
        Assert.True(builder.ConnectionReset);
        Assert.Equal("Sufficit.Identity.Tests", builder.ApplicationName);
        Assert.Equal("secret", builder.Password);
    }

    [Fact]
    public void Development_test_sentinel_remains_supported()
    {
        var result = Sufficit.Identity.STS.ServiceCollectionExtensions
            .ApplyDatabaseConnectionPolicy(
                "unused",
                new DatabaseConnectionPoolOptions(),
                tolerateInvalidDevelopmentValue: true);

        Assert.Equal("unused", result);
    }

    [Fact]
    public void Runtime_telemetry_tracks_active_connection_and_commands_without_sql()
    {
        using var telemetry = new DatabaseRuntimeTelemetry();
        using var connection = new SqliteConnection("Data Source=:memory:");
        connection.Open();

        telemetry.ConfigureWatchdog(enabled: true);
        telemetry.TrackOpened(connection);
        telemetry.TrackCommandStarted(connection);
        telemetry.TrackCommandCompleted(
            connection,
            TimeSpan.FromMilliseconds(3.5),
            failed: false);
        telemetry.TrackCommandStarted(connection);

        var active = telemetry.GetSnapshot();
        var observed = Assert.Single(active.ActiveConnections);
        Assert.Equal("SQLite", observed.Provider);
        Assert.Equal(2, observed.CommandCount);
        Assert.Equal(2, observed.LeaseCommandCount);
        Assert.Equal(1, observed.ActiveCommands);
        Assert.Equal(2, active.TotalCommands);
        Assert.Equal("starting", active.Watchdog.Status);

        telemetry.TrackCommandCompleted(
            connection,
            TimeSpan.FromMilliseconds(8),
            failed: true);
        telemetry.TrackClosed(connection);

        var returned = telemetry.GetSnapshot();
        Assert.Empty(returned.ActiveConnections);
        Assert.Equal(2, returned.TotalCommands);
        Assert.Equal(1, returned.FailedCommands);
    }

    [Fact]
    public void Watchdog_snapshot_exposes_only_sanitized_failure_state()
    {
        using var telemetry = new DatabaseRuntimeTelemetry();
        telemetry.ConfigureWatchdog(enabled: true);
        telemetry.RecordWatchdogProbe(
            healthy: false,
            consecutiveFailures: 2,
            TimeSpan.FromSeconds(10),
            "database_probe_timeout");

        var watchdog = telemetry.GetSnapshot().Watchdog;

        Assert.Equal("degraded", watchdog.Status);
        Assert.Equal(2, watchdog.ConsecutiveFailures);
        Assert.Equal("database_probe_timeout", watchdog.LastFailureCode);
        Assert.DoesNotContain("connection string", watchdog.LastFailureCode);
    }
}
