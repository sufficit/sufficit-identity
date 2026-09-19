using Microsoft.Extensions.Configuration;
using Sufficit.Identity.Application.Security;

namespace Sufficit.Identity.Vault;

/// <summary>
/// Reports startup secrets that a configuration provider supplied instead of
/// the approved secret boundary, and credential-looking configuration keys
/// nobody mapped.
/// </summary>
/// <remarks>
/// <see cref="SecretConfigurationExtensions.EnsureNoPlaintextSecrets"/> already
/// refuses startup for the seventeen mapped keys. This covers what that gate
/// cannot see: a secret that was never mapped, and — once a deployment declares
/// its migration complete — any remaining configuration fallback.
///
/// Only names and sources leave this type. Proving a secret came from the right
/// place never requires reading it.
/// </remarks>
public sealed class SecretBoundaryPostureContributor(
    IConfiguration configuration,
    SecretResolutionReport report)
    : IProductionPostureContributor
{
    /// <summary>
    /// Set by a deployment that has finished moving its secrets, after which a
    /// configuration fallback is a regression rather than a migration state.
    /// </summary>
    public const string MigrationCompleteKey =
        "Sufficit:Vault:SecretMigrationComplete";

    public IEnumerable<ProductionPostureFinding> Evaluate()
    {
        var unmapped = SecretConfigurationExtensions
            .FindUnmappedSecretLikeKeys(configuration);
        if (unmapped.Count > 0)
        {
            yield return new(
                "configuration-unmapped-secret",
                "Configuration holds credential-looking values that are not "
                + "mapped to the secret boundary, so nothing moves them out or "
                + "keeps them out: "
                + string.Join(", ", unmapped) + ".",
                "Move each value to a SUFFICIT_SECRET_* variable and add its "
                + "logical name to the override table, or rename the key if it "
                + "is not a credential.",
                Severity: ProductionPostureSeverity.Advisory);
        }

        foreach (var finding in WorldReadableConfigurationFiles())
        {
            yield return finding;
        }

        var fallbacks = report.ConfigurationFallbacks;
        if (fallbacks.Count == 0)
        {
            yield break;
        }

        var migrationComplete = configuration.GetValue(
            MigrationCompleteKey,
            defaultValue: false);

        yield return new(
            "secret-configuration-fallback",
            "Startup secrets resolved from a configuration provider rather "
            + "than the secret store: "
            + string.Join(
                ", ",
                fallbacks.Select(resolution => resolution.LogicalName))
            + ".",
            "Publish each one as its SUFFICIT_SECRET_* variable and remove the "
            + "configuration value. Once every host is migrated, set "
            + MigrationCompleteKey + "=true so a reintroduced fallback refuses "
            + "startup.",
            // Before the deployment declares the migration finished, a
            // fallback is the state being migrated out of. After, it is a
            // regression, and the whole point of declaring it is that the
            // next one cannot arrive quietly.
            Severity: migrationComplete
                ? ProductionPostureSeverity.Blocking
                : ProductionPostureSeverity.Advisory);
    }

    /// <summary>
    /// Configuration files any account on the host can read.
    /// </summary>
    /// <remarks>
    /// A file permission is the last boundary around a value that made it into
    /// a file anyway — the machine-specific file and the local deployment
    /// reference both hold real endpoints, and `deploy/local/appsettings.json`
    /// has already been mistaken for production configuration once
    /// (evaluation 2026-08-15, H-1). Reports the path and the mode; the
    /// contents are never read.
    /// </remarks>
    private IEnumerable<ProductionPostureFinding> WorldReadableConfigurationFiles()
    {
        if (!OperatingSystem.IsLinux() && !OperatingSystem.IsMacOS())
        {
            yield break;
        }

        if (configuration is not IConfigurationRoot root)
        {
            yield break;
        }

        var exposed = new List<string>();
        foreach (var provider in root.Providers.OfType<FileConfigurationProvider>())
        {
            var path = provider.Source.Path;
            if (string.IsNullOrWhiteSpace(path)
                || provider.Source.FileProvider?.GetFileInfo(path)?.PhysicalPath
                    is not { } physical
                || !File.Exists(physical))
            {
                continue;
            }

            var mode = File.GetUnixFileMode(physical);
            if (mode.HasFlag(UnixFileMode.OtherRead))
            {
                exposed.Add($"{Path.GetFileName(physical)} ({mode})");
            }
        }

        if (exposed.Count > 0)
        {
            yield return new(
                "configuration-file-world-readable",
                "Configuration files are readable by every account on the "
                + "host: " + string.Join(", ", exposed) + ".",
                "Restrict them to the service account and its group "
                + "(chmod 640, owner root, group of the service user).",
                Severity: ProductionPostureSeverity.Advisory);
        }
    }
}
