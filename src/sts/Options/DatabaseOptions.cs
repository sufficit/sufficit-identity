using Sufficit.Identity.Application.Security;

namespace Sufficit.Identity.STS;

/// <summary>
/// Database schema provisioning/migration policy.
/// </summary>
/// <remarks>
/// <para>
/// <b>Dev/test</b> always runs <c>Database.MigrateAsync()</c> at startup (so
/// pending EF migrations are applied and the Up/Down paths are exercised
/// end-to-end, not just <c>EnsureCreated</c> which ignores migrations).
/// </para>
/// <para>
/// <b>Production</b> applies pending EF migrations at startup ONLY when
/// <see cref="AutoMigrate"/> is <c>true</c> (default <c>false</c> — the
/// conservative choice for the legacy shared Duende/Skoruba database, which
/// predates the EF model and was migrated into). Because applying migrations
/// to the wrong database is destructive, <see cref="AllowedDatabaseNames"/>
/// acts as a guard: when non-empty, the actual database name (parsed from the
/// connection string) MUST be in that allow-list or the process refuses to
/// start. This stops a misconfigured connection string from ever pointing the
/// migrator at the production database by accident.
/// </para>
/// </remarks>
public sealed class DatabaseOptions
{
    /// <summary>
    /// Transport contract for the database connection. Compatibility keeps
    /// existing rolling deployments unchanged; production can select
    /// <c>RequireVerifiedTls</c> or the explicit <c>PrivateSocket</c>
    /// exception after its CA/socket is provisioned.
    /// </summary>
    public DatabaseTransportMode TransportMode { get; init; } =
        DatabaseTransportMode.Compatibility;

    /// <summary>
    /// When <c>true</c> outside Development, the host applies pending EF Core
    /// migrations on startup via <c>Database.MigrateAsync()</c>. Default
    /// <c>false</c>: production keeps provisioning schema from the checked-in
    /// canonical SQL (<c>docs/migration/sql/*</c>) until an operator
    /// deliberately opts in. Flip to <c>true</c> only after confirming the
    /// schema is aligned and <see cref="AllowedDatabaseNames"/> is set.
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
