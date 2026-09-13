using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Routing;
using Microsoft.Extensions.Configuration;
using Sufficit.Identity.Hosting;
using Sufficit.Identity.Server;
using Sufficit.Identity.UI.Vault;
using Xunit;

namespace Sufficit.Identity.Tests;

/// <summary>
/// Composes the public UI and Vault UI modules on a real
/// <see cref="WebApplication"/>, the way Program.cs does, and checks the mapped
/// endpoints. The integration test factory builds its own pipeline, so this is
/// what exercises the module contributions themselves.
/// </summary>
public sealed class PublicUiModuleCompositionTests
{
    [Fact]
    public void Embedded_vault_pages_join_the_public_blazor_endpoint()
    {
        var routes = ComposeRoutes(new Dictionary<string, string?>());

        Assert.Contains("/device/launch", routes);
        Assert.Contains("/culture/set", routes);
        Assert.Contains("/vault", routes);
    }

    [Fact]
    public void Disabled_vault_ui_contributes_no_pages_to_the_public_endpoint()
    {
        var routes = ComposeRoutes(new Dictionary<string, string?>
        {
            [VaultUiIdentityModule.EnabledSetting] = "false",
        });

        Assert.Contains("/device/launch", routes);
        Assert.DoesNotContain("/vault", routes);
    }

    private static HashSet<string> ComposeRoutes(Dictionary<string, string?> settings)
    {
        var builder = WebApplication.CreateBuilder(new WebApplicationOptions
        {
            EnvironmentName = "Development",
            // The composition host's static web assets manifest, copied to
            // the test output by the server project reference.
            ApplicationName = typeof(PublicUiIdentityModule).Assembly.GetName().Name,
            ContentRootPath = AppContext.BaseDirectory,
        });
        builder.Configuration.AddInMemoryCollection(settings);

        var modules = IdentityModuleCatalog.Create(
            builder.Configuration,
            new VaultUiIdentityModule(),
            new PublicUiIdentityModule());
        modules.ConfigureServices(builder.Services, builder.Configuration);

        var app = builder.Build();
        var pipeline = new IdentityPipelineBuilder();
        modules.ConfigurePipeline(pipeline);
        pipeline.ApplyStage(app, IdentityPipelineStage.PreAuthentication);
        pipeline.ApplyStage(app, IdentityPipelineStage.Endpoints);
        pipeline.EnsureAllApplied();

        return ((IEndpointRouteBuilder)app).DataSources
            .SelectMany(source => source.Endpoints)
            .OfType<RouteEndpoint>()
            .Select(endpoint => "/" + endpoint.RoutePattern.RawText?.TrimStart('/'))
            .ToHashSet(StringComparer.OrdinalIgnoreCase);
    }
}
