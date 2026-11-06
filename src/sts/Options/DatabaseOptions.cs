using Sufficit.Identity.Application.Security;

namespace Sufficit.Identity.STS;

/// <summary>
/// Database schema provisioning/migration policy.
/// </summary>
/// <remarks>
/// <para>
/// <b>Development</b> applies pending EF migrations during startup.
/// Other environments use the dedicated <c>--migrate-only</c> process;
/// the HTTP host does not provision schema.
/// </para>
/// <para>
/// The HTTP host rejects <see cref="AutoMigrate"/> when enabled outside
/// Development. The dedicated migrator does not require that legacy switch.
/// Whenever migration is selected, a non-empty <see cref="AllowedDatabaseNames"/>
/// list restricts the target database before schema changes are applied.
/// </para>
/// </remarks>
public sealed class DatabaseOptions
{
    /// <summary>
    /// Opt in for Galera deployments: add the causal READ bit to every application
    /// EF connection's wsrep_sync_wait setting and disable session dirty reads.
    /// Requires wsrep enabled. Setup
    /// failures abort connection use; no global server setting is changed.
    /// Already cached tickets still follow the configured cache lifetime.
    /// </summary>
    public bool RequireGaleraCausalReads { get; init; }

    /// <summary>
    /// Transport contract for the database connection. Compatibility keeps
    /// existing rolling deployments unchanged; production can select
    /// <c>RequireVerifiedTls</c> or the explicit <c>PrivateSocket</c>
    /// exception after its CA/socket is provisioned.
    /// </summary>
    public DatabaseTransportMode TransportMode { get; init; } =
        DatabaseTransportMode.Compatibility;

    /// <summary>
    /// Legacy startup switch retained for configuration compatibility.
    /// Enabling it outside Development causes the HTTP host to refuse startup.
    /// Use the dedicated <c>--migrate-only</c> deployment process instead.
    /// Development and the dedicated migrator select migration independently
    /// of this flag, subject to <see cref="AllowedDatabaseNames"/>.
    /// </summary>
    public bool AutoMigrate { get; init; } = false;

    /// <summary>
    /// Allow-list of database names the automatic migrator is permitted to
    /// touch. When non-empty (recommended in production), the database name
    /// parsed from the active connection string MUST appear here or startup
    /// fails fast — a guard against pointing the migrator at the wrong
    /// (e.g. production) database. Empty (the default) disables the guard
    /// and trusts the connection string unconditionally; acceptable in
    /// Development.
    /// </summary>
    public string[] AllowedDatabaseNames { get; init; } = [];

    /// <summary>
    /// Connection-pool limits and timeouts applied by the STS before the
    /// provider is configured. See <see cref="DatabaseConnectionPoolOptions"/>.
    /// </summary>
    public DatabaseConnectionPoolOptions ConnectionPool { get; init; } = new();

    /// <summary>
    /// In-process database watchdog policy. See
    /// <see cref="DatabaseWatchdogOptions"/>.
    /// </summary>
    public DatabaseWatchdogOptions Watchdog { get; init; } = new();
}
public enum DatabaseTransportMode
{
    Compatibility,
    RequireVerifiedTls,
    PrivateSocket,
}
/// <summary>
/// Safe defaults for the current MySQL/MariaDB connection provider. Every
/// value is explicit so deployments do not inherit driver-default drift.
/// </summary>
public sealed class DatabaseConnectionPoolOptions
{
    public int MaximumSize { get; init; } = 50;

    public int MinimumSize { get; init; } = 0;

    public int ConnectionTimeoutSeconds { get; init; } = 15;

    public int CommandTimeoutSeconds { get; init; } = 30;

    public int ConnectionLifetimeSeconds { get; init; } = 180;

    public int ConnectionIdleTimeoutSeconds { get; init; } = 180;

    public bool ResetOnCheckout { get; init; } = true;

    /// <summary>
    /// Non-secret pool label emitted by MySqlConnector metrics and server
    /// connection attributes.
    /// </summary>
    public string ApplicationName { get; init; } = "Sufficit.Identity";
}
/// <summary>
/// Detects the state in which the process remains alive but cannot obtain a
/// usable database connection. After sustained failures it asks the host to
/// stop with a failure exit code so systemd or the container orchestrator can
/// rebuild the process and its pools.
/// </summary>
public sealed class DatabaseWatchdogOptions
{
    public bool Enabled { get; init; } = true;

    public int StartupDelaySeconds { get; init; } = 60;

    public int ProbeIntervalSeconds { get; init; } = 30;

    public int ProbeTimeoutSeconds { get; init; } = 10;

    public int ConsecutiveFailuresBeforeRestart { get; init; } = 3;
}
