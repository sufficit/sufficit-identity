using Microsoft.Extensions.Configuration;
using Sufficit.Identity.Server;
using Xunit;

namespace Sufficit.Identity.Tests;

public sealed class MachineSpecificConfigurationTests
{
    [Fact]
    public void Machine_specific_file_is_lowercase_and_overrides_environment_settings()
    {
        var directory = Directory.CreateTempSubdirectory("sufficit-identity-config-");

        try
        {
            File.WriteAllText(
                Path.Combine(directory.FullName, "appsettings.Production.json"),
                """{"Test":{"Source":"environment","Common":"preserved"}}""");
            File.WriteAllText(
                Path.Combine(directory.FullName, "appsettings.eveo-apps.json"),
                """{"Test":{"Source":"machine"}}""");

            var configuration = new ConfigurationBuilder()
                .SetBasePath(directory.FullName)
                .AddJsonFile("appsettings.Production.json", optional: false)
                .AddMachineSpecificJsonFile("  EVEO-APPS  ")
                .Build();
            using var disposableConfiguration = configuration as IDisposable;

            Assert.Equal("machine", configuration["Test:Source"]);
            Assert.Equal("preserved", configuration["Test:Common"]);
        }
        finally
        {
            directory.Delete(recursive: true);
        }
    }

    [Fact]
    public void Missing_machine_specific_file_is_optional()
    {
        var directory = Directory.CreateTempSubdirectory("sufficit-identity-config-");

        try
        {
            var configuration = new ConfigurationBuilder()
                .SetBasePath(directory.FullName)
                .AddInMemoryCollection(new Dictionary<string, string?>
                {
                    ["Test:Source"] = "environment",
                })
                .AddMachineSpecificJsonFile("SERVER-WITHOUT-FILE")
                .Build();
            using var disposableConfiguration = configuration as IDisposable;

            Assert.Equal("environment", configuration["Test:Source"]);
        }
        finally
        {
            directory.Delete(recursive: true);
        }
    }
}
