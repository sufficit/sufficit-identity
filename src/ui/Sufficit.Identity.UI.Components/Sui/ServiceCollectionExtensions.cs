using System;
using Microsoft.Extensions.DependencyInjection;
using Sufficit.Blazor.UI.Themes;

namespace Sufficit.Blazor.UI;

/// <summary>
/// Registers the repository-local SUI theme contract used by Identity.
/// </summary>
public static class ServiceCollectionExtensions
{
    public static IServiceCollection AddSufficitUI(
        this IServiceCollection services,
        Action<SUIThemeOptions>? configure = null)
    {
        var options = new SUIThemeOptions();
        configure?.Invoke(options);

        var theme = options.Theme ?? DefaultSUITheme.Instance;
        services.AddScoped<ISUITheme>(_ => theme);
        return services;
    }
}
