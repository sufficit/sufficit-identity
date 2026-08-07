using System.Data.Common;
using Microsoft.EntityFrameworkCore.Diagnostics;

namespace Sufficit.Identity.STS.Diagnostics;

internal sealed class DatabaseConnectionTelemetryInterceptor(
    DatabaseRuntimeTelemetry telemetry) : DbConnectionInterceptor
{
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
