using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;

namespace Sufficit.Identity.Hosting;

/// <summary>
/// A feature module that a composition host can enable without knowing its
/// internals: it registers its own services and contributes pipeline steps at
/// named stages instead of positions in the host.
/// </summary>
public interface IIdentityModule
{
    /// <summary>Stable, unique identifier, such as <c>scim</c>.</summary>
    string Id { get; }

    /// <summary>Reads the module's own configuration flag.</summary>
    bool IsEnabled(IConfiguration configuration);

    void ConfigureServices(IServiceCollection services, IConfiguration configuration);

    /// <summary>
    /// Contributes middleware or endpoints. The builder applies contributions
    /// by <see cref="IdentityPipelineStage"/>, so a module never depends on the
    /// position of a line in the host.
    /// </summary>
    void ConfigurePipeline(IdentityPipelineBuilder pipeline)
    {
    }
}
