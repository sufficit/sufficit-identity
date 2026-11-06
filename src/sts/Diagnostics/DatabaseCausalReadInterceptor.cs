using System.Data.Common;
using Microsoft.EntityFrameworkCore.Diagnostics;

namespace Sufficit.Identity.STS.Diagnostics;

/// <summary>Explicit Galera policy for logical EF connections, including pooled leases.</summary>
internal sealed class DatabaseCausalReadInterceptor : DbConnectionInterceptor
{
    private static DbCommand Setup(DbConnection connection)
    {
        var command = connection.CreateCommand();
        command.CommandTimeout = 10;
        // Dirty reads bypass sync-wait. Disable them for this opted-in session,
        // preserving existing write/SHOW bits. Never change GLOBAL settings.
        command.CommandText = "SET SESSION wsrep_dirty_reads = OFF; SET SESSION wsrep_sync_wait = @@SESSION.wsrep_sync_wait | 1; SELECT @@SESSION.wsrep_on AND NOT @@SESSION.wsrep_dirty_reads";
        return command;
    }

    private static void RequireWsrep(object? value)
    {
        if (value is null || value == DBNull.Value || !Convert.ToBoolean(value))
            throw new InvalidOperationException("Galera causal reads require wsrep enabled and dirty reads disabled on the selected database session.");
    }

    public override void ConnectionOpened(DbConnection connection, ConnectionEndEventData eventData)
    {
        using var command = Setup(connection);
        RequireWsrep(command.ExecuteScalar());
    }

    public override async Task ConnectionOpenedAsync(DbConnection connection, ConnectionEndEventData eventData,
        CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();
        await using var command = Setup(connection);
        RequireWsrep(await command.ExecuteScalarAsync(cancellationToken));
    }
}
