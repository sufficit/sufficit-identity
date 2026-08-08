using System.Data.Common;
using Microsoft.EntityFrameworkCore.Diagnostics;

namespace Sufficit.Identity.STS.Diagnostics;

internal sealed class DatabaseConnectionTelemetryInterceptor(
    DatabaseRuntimeTelemetry telemetry) : DbConnectionInterceptor
{
    // Providers differ in which connection lifecycle callback they raise when
    // returning a pooled connection. Remove the logical lease at the earliest
    // closing/disposal signal; TrackClosed is intentionally idempotent.
    public override InterceptionResult ConnectionClosing(
        DbConnection connection,
        ConnectionEventData eventData,
        InterceptionResult result)
    {
        telemetry.TrackClosed(connection);
        return result;
    }

    public override ValueTask<InterceptionResult> ConnectionClosingAsync(
        DbConnection connection,
        ConnectionEventData eventData,
        InterceptionResult result)
    {
        telemetry.TrackClosed(connection);
        return ValueTask.FromResult(result);
    }

    public override void ConnectionOpened(
        DbConnection connection,
        ConnectionEndEventData eventData) => telemetry.TrackOpened(connection);

    public override Task ConnectionOpenedAsync(
        DbConnection connection,
        ConnectionEndEventData eventData,
        CancellationToken cancellationToken = default)
    {
        telemetry.TrackOpened(connection);
        return Task.CompletedTask;
    }

    public override void ConnectionClosed(
        DbConnection connection,
        ConnectionEndEventData eventData) => telemetry.TrackClosed(connection);

    public override Task ConnectionClosedAsync(
        DbConnection connection,
        ConnectionEndEventData eventData)
    {
        telemetry.TrackClosed(connection);
        return Task.CompletedTask;
    }

    public override InterceptionResult ConnectionDisposing(
        DbConnection connection,
        ConnectionEventData eventData,
        InterceptionResult result)
    {
        telemetry.TrackClosed(connection);
        return result;
    }

    public override ValueTask<InterceptionResult> ConnectionDisposingAsync(
        DbConnection connection,
        ConnectionEventData eventData,
        InterceptionResult result)
    {
        telemetry.TrackClosed(connection);
        return ValueTask.FromResult(result);
    }

    public override void ConnectionDisposed(
        DbConnection connection,
        ConnectionEndEventData eventData) => telemetry.TrackClosed(connection);

    public override Task ConnectionDisposedAsync(
        DbConnection connection,
        ConnectionEndEventData eventData)
    {
        telemetry.TrackClosed(connection);
        return Task.CompletedTask;
    }

    public override void ConnectionFailed(
        DbConnection connection,
        ConnectionErrorEventData eventData) => telemetry.TrackClosed(connection);

    public override Task ConnectionFailedAsync(
        DbConnection connection,
        ConnectionErrorEventData eventData,
        CancellationToken cancellationToken = default)
    {
        telemetry.TrackClosed(connection);
        return Task.CompletedTask;
    }
}
