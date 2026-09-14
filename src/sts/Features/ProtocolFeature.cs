using Microsoft.Extensions.DependencyInjection;
using Microsoft.IdentityModel.Tokens;
using OpenIddict.Server;

namespace Sufficit.Identity.STS.Features;

/// <summary>What a protocol feature receives from the STS composition.</summary>
internal sealed record ProtocolFeatureContext(
    SufficitIdentityOptions Options,
    SigningCredentials AuxiliarySigningCredentials);

/// <summary>
/// One optional protocol capability of the STS with all of its composition in
/// one place: option validation, services, OpenIddict server configuration,
/// discovery metadata and the runtime capabilities it adds.
/// </summary>
/// <remarks>
/// Internal to the STS on purpose: this is where OpenIddict is configured, so
/// the contract stays out of the hosting abstractions implemented by modules
/// outside the STS (A8, maintainer decision 2026-09-14). Every hook runs
/// whether or not the feature is enabled; a disabled feature registers its own
/// fallbacks and publishes its own "not supported" metadata.
/// </remarks>
internal interface IProtocolFeature
{
    /// <summary>Stable identifier, unique within the catalog.</summary>
    string Name { get; }

    bool IsEnabled(SufficitIdentityOptions options);

    IEnumerable<string> RuntimeCapabilities(SufficitIdentityOptions options) => [];

    /// <summary>Rejects unsupported option values at startup.</summary>
    void Validate(SufficitIdentityOptions options)
    {
    }

    void ConfigureServices(IServiceCollection services, ProtocolFeatureContext context)
    {
    }

    void ConfigureServer(OpenIddictServerBuilder server, ProtocolFeatureContext context)
    {
    }

    void ConfigureDiscovery(
        OpenIddictServerEvents.HandleConfigurationRequestContext discovery,
        ProtocolFeatureContext context)
    {
    }
}

/// <summary>
/// The protocol features of the STS, in composition order. The STS composition
/// root, the OpenIddict server configuration, the discovery handler and the
/// runtime capability catalog iterate this list instead of testing each
/// feature's options.
/// </summary>
internal static class ProtocolFeatureCatalog
{
    public static IReadOnlyList<IProtocolFeature> All { get; } =
    [
        new IdentityAssertionProtocolFeature(),
        new CibaProtocolFeature(),
        new JarmProtocolFeature(),
        new SharedSignalsProtocolFeature(),
    ];

    public static void Validate(SufficitIdentityOptions options)
    {
        foreach (var feature in All)
        {
            feature.Validate(options);
        }
    }

    public static void ConfigureServices(IServiceCollection services, ProtocolFeatureContext context)
    {
        foreach (var feature in All)
        {
            feature.ConfigureServices(services, context);
        }
    }

    public static void ConfigureServer(OpenIddictServerBuilder server, ProtocolFeatureContext context)
    {
        foreach (var feature in All)
        {
            feature.ConfigureServer(server, context);
        }
    }

    public static void ConfigureDiscovery(
        OpenIddictServerEvents.HandleConfigurationRequestContext discovery,
        ProtocolFeatureContext context)
    {
        foreach (var feature in All)
        {
            feature.ConfigureDiscovery(discovery, context);
        }
    }

    public static IEnumerable<string> RuntimeCapabilities(SufficitIdentityOptions options) =>
        All.SelectMany(feature => feature.RuntimeCapabilities(options));
}
