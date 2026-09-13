using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;

namespace Sufficit.Identity.Hosting;

/// <summary>
/// The modules a host composes, given explicitly so the set is auditable, and
/// filtered to the ones their configuration enables.
/// </summary>
public sealed class IdentityModuleCatalog
{
    private IdentityModuleCatalog(IReadOnlyList<IIdentityModule> enabled)
    {
        Enabled = enabled;
    }

    /// <summary>Enabled modules, in the order the host listed them.</summary>
    public IReadOnlyList<IIdentityModule> Enabled { get; }

    public static IdentityModuleCatalog Create(
        IConfiguration configuration,
        params IIdentityModule[] modules)
    {
        ArgumentNullException.ThrowIfNull(configuration);
        ArgumentNullException.ThrowIfNull(modules);

        var duplicate = modules
            .GroupBy(module => module.Id, StringComparer.Ordinal)
            .FirstOrDefault(group => group.Count() > 1);
        if (duplicate is not null)
        {
            throw new InvalidOperationException(
                $"The identity module '{duplicate.Key}' is registered more than once.");
        }

        return new IdentityModuleCatalog(
            modules.Where(module => module.IsEnabled(configuration)).ToArray());
    }

    public bool IsEnabled(string id) =>
        Enabled.Any(module => string.Equals(module.Id, id, StringComparison.Ordinal));

    public void ConfigureServices(IServiceCollection services, IConfiguration configuration)
    {
        foreach (var module in Enabled)
        {
            module.ConfigureServices(services, configuration);
        }
    }

    public void ConfigurePipeline(IdentityPipelineBuilder pipeline)
    {
        ArgumentNullException.ThrowIfNull(pipeline);
        var previousOwner = pipeline.Owner;
        try
        {
            foreach (var module in Enabled)
            {
                pipeline.Owner = module.Id;
                module.ConfigurePipeline(pipeline);
            }
        }
        finally
        {
            pipeline.Owner = previousOwner;
        }
    }
}
