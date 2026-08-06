using Microsoft.Extensions.Configuration;

namespace Sufficit.Identity.Server;

/// <summary>
/// Adds the conventional Sufficit machine-specific configuration layer.
/// </summary>
public static class MachineSpecificConfigurationExtensions
{
    /// <summary>
    /// Loads <c>appsettings.{hostname}.json</c> using a trimmed, lowercase
    /// machine name. The file is optional and is appended after the standard
    /// ASP.NET Core environment-specific sources.
    /// </summary>
    public static IConfigurationBuilder AddMachineSpecificJsonFile(
        this IConfigurationBuilder configuration,
        string? machineName = null)
    {
        ArgumentNullException.ThrowIfNull(configuration);

        var normalized = (machineName ?? Environment.MachineName)
            .Trim()
            .ToLowerInvariant();

        if (normalized.Length == 0)
        {
            return configuration;
        }

        return configuration.AddJsonFile(
            $"appsettings.{normalized}.json",
            optional: true,
            reloadOnChange: true);
    }
}
