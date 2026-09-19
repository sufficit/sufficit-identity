namespace Sufficit.Identity.Vault;

/// <summary>Where a startup secret's value came from.</summary>
public enum SecretResolutionSource
{
    /// <summary>Not configured anywhere.</summary>
    Absent,

    /// <summary>The approved <see cref="ISecretStore"/> boundary.</summary>
    SecretStore,

    /// <summary>
    /// A configuration provider — an appsettings file, the machine-specific
    /// file, User Secrets. The legacy fallback.
    /// </summary>
    Configuration,
}

/// <summary>
/// Where one startup secret resolved from, carrying no part of its value.
/// </summary>
/// <remarks>
/// Deliberately not a value holder. Startup needs to prove that a secret came
/// from the approved boundary, and that question is answerable without ever
/// reading the secret — so this type is built so that it cannot accidentally
/// be logged with one.
/// </remarks>
public sealed record SecretResolution(
    string LogicalName,
    string ConfigurationKey,
    SecretResolutionSource Source)
{
    public override string ToString() =>
        $"{LogicalName} ({ConfigurationKey}) <- {Source}";
}

/// <summary>
/// The provenance of every known startup secret, for a redacted deployment
/// report and for the production gate.
/// </summary>
public sealed record SecretResolutionReport(
    IReadOnlyList<SecretResolution> Resolutions)
{
    /// <summary>
    /// Secrets a configuration provider supplied instead of the secret store.
    /// </summary>
    public IReadOnlyList<SecretResolution> ConfigurationFallbacks =>
        [.. Resolutions.Where(resolution =>
            resolution.Source == SecretResolutionSource.Configuration)];

    /// <summary>A redacted, stable summary — logical names and sources only.</summary>
    public override string ToString() =>
        string.Join("; ", Resolutions.Select(resolution => resolution.ToString()));
}
