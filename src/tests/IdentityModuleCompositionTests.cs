using Microsoft.AspNetCore.Builder;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Sufficit.Identity.Hosting;
using Xunit;

namespace Sufficit.Identity.Tests;

public sealed class IdentityModuleCompositionTests
{
    [Fact]
    public void Pipeline_steps_run_by_stage_then_registration_order()
    {
        var pipeline = new IdentityPipelineBuilder();
        var applied = new List<string>();

        pipeline.Use(IdentityPipelineStage.Endpoints, "endpoints", _ => applied.Add("endpoints"));
        pipeline.Use(IdentityPipelineStage.Authentication, "authentication", _ => applied.Add("authentication"));
        pipeline.Use(IdentityPipelineStage.Cors, "cors", _ => applied.Add("cors"));
        pipeline.Use(IdentityPipelineStage.Authentication, "authentication-extra", _ => applied.Add("authentication-extra"));
        pipeline.Use(IdentityPipelineStage.Forwarding, "forwarding", _ => applied.Add("forwarding"));

        pipeline.Apply(new ApplicationBuilder(new ServiceCollection().BuildServiceProvider()));

        string[] expected = ["forwarding", "cors", "authentication", "authentication-extra", "endpoints"];
        Assert.Equal(expected, applied);
        Assert.Equal(expected, pipeline.Steps.Select(step => step.Name));
    }

    [Fact]
    public void Duplicate_step_names_are_rejected()
    {
        var pipeline = new IdentityPipelineBuilder();
        pipeline.Use(IdentityPipelineStage.Routing, "routing", _ => { });

        Assert.Throws<InvalidOperationException>(() =>
            pipeline.Use(IdentityPipelineStage.Endpoints, "routing", _ => { }));
    }

    [Fact]
    public void Catalog_composes_only_enabled_modules_and_records_their_steps()
    {
        var configuration = new ConfigurationBuilder()
            .AddInMemoryCollection(new Dictionary<string, string?>
            {
                ["Modules:alpha"] = "true",
                ["Modules:beta"] = "false",
            })
            .Build();
        var alpha = new FakeModule("alpha");
        var beta = new FakeModule("beta");

        var catalog = IdentityModuleCatalog.Create(configuration, alpha, beta);
        var services = new ServiceCollection();
        catalog.ConfigureServices(services, configuration);
        var pipeline = new IdentityPipelineBuilder();
        catalog.ConfigurePipeline(pipeline);

        Assert.True(catalog.IsEnabled("alpha"));
        Assert.False(catalog.IsEnabled("beta"));
        Assert.True(alpha.ServicesConfigured);
        Assert.False(beta.ServicesConfigured);
        var step = Assert.Single(pipeline.Steps);
        Assert.Equal("alpha", step.Owner);
        Assert.Equal("host", pipeline.Owner);
    }

    [Fact]
    public void Catalog_rejects_duplicate_module_ids()
    {
        var configuration = new ConfigurationBuilder().Build();

        Assert.Throws<InvalidOperationException>(() =>
            IdentityModuleCatalog.Create(configuration, new FakeModule("same"), new FakeModule("same")));
    }

    private sealed class FakeModule(string id) : IIdentityModule
    {
        public string Id { get; } = id;

        public bool ServicesConfigured { get; private set; }

        public bool IsEnabled(IConfiguration configuration) =>
            configuration.GetValue<bool>($"Modules:{Id}");

        public void ConfigureServices(IServiceCollection services, IConfiguration configuration) =>
            ServicesConfigured = true;

        public void ConfigurePipeline(IdentityPipelineBuilder pipeline) =>
            pipeline.Use(IdentityPipelineStage.PostAuthorization, $"{Id}-step", _ => { });
    }
}
