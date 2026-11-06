using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;
using Sufficit.Identity.STS;
using Xunit;

namespace Sufficit.Identity.Tests;

public sealed class ManagementOptionsBindingTests
{
    [Fact]
    public void RootAndManagementSectionUseTheSameContractAndSettings()
    {
        var configuration = new ConfigurationBuilder().AddInMemoryCollection(
            new Dictionary<string, string?>
            {
                ["Sufficit:Identity:Management:Enabled"] = "true",
                ["Sufficit:Identity:Management:RoutePrefix"] = "management-api",
                ["Sufficit:Identity:Management:RequiredScope"] = "provider.manage",
                ["Sufficit:Identity:Management:AvatarPictureOrigins:0"] = "https://avatars.example.test",
                ["Sufficit:Identity:Management:RequireMfa"] = "false",
                ["Sufficit:Identity:Management:AuditRetentionDays"] = "30"
            }).Build();
        var services = new ServiceCollection();
        services.AddOptions<SufficitIdentityOptions>()
            .Bind(configuration.GetSection("Sufficit:Identity"));
        services.AddOptions<Sufficit.Identity.Management.ManagementOptions>()
            .Bind(configuration.GetSection("Sufficit:Identity:Management"));
        using var provider = services.BuildServiceProvider();
        var root = provider.GetRequiredService<IOptions<SufficitIdentityOptions>>().Value;
        var management = provider.GetRequiredService<IOptions<Sufficit.Identity.Management.ManagementOptions>>().Value;
        var nested = Assert.IsType<Sufficit.Identity.Management.ManagementOptions>(root.Management);

        Assert.True(nested.Enabled);
        Assert.True(nested.RequireAuthorization);
        Assert.Equal("management-api", nested.RoutePrefix);
        Assert.Equal("provider.manage", nested.RequiredScope);
        Assert.Equal(new[] { "https://avatars.example.test" }, nested.AvatarPictureOrigins);
        Assert.False(nested.RequireMfa);
        Assert.Equal(30, nested.AuditRetentionDays);
        Assert.Equal(management.Enabled, nested.Enabled);
        Assert.Equal(management.RequireAuthorization, nested.RequireAuthorization);
        Assert.Equal(management.RoutePrefix, nested.RoutePrefix);
        Assert.Equal(management.RequiredScope, nested.RequiredScope);
        Assert.Equal(management.AvatarPictureOrigins, nested.AvatarPictureOrigins);
        Assert.Equal(management.RequireMfa, nested.RequireMfa);
        Assert.Equal(management.AuditRetentionDays, nested.AuditRetentionDays);
    }
}
