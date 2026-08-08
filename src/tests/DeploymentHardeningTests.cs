using System.Diagnostics;

using Xunit;

namespace Sufficit.Identity.Tests;

public sealed class DeploymentHardeningTests
{
    [Fact]
    public void Systemd_preflight_is_unprivileged_root_owned_and_fail_closed()
    {
        var repository = ResolveRepository();
        var service = File.ReadAllText(Path.Combine(
            repository,
            "helpers/sufficit-identity.service"));
        Assert.Contains(
            "ExecStartPre=/usr/libexec/sufficit-identity/prestart.sh",
            service,
            StringComparison.Ordinal);
        Assert.DoesNotContain("ExecStartPre=+-", service, StringComparison.Ordinal);
        Assert.DoesNotContain(
            "/opt/sufficit-identity/helpers/prestart.sh",
            service,
            StringComparison.Ordinal);
        Assert.Contains("NoNewPrivileges=true", service, StringComparison.Ordinal);
        Assert.Contains("ProtectSystem=strict", service, StringComparison.Ordinal);
        Assert.Contains("CapabilityBoundingSet=", service, StringComparison.Ordinal);
        Assert.Contains(
            "ReadWritePaths=/run/sufficit-identity",
            service,
            StringComparison.Ordinal);
    }

    [Fact]
    public void Runtime_preflight_cannot_prepare_or_reown_a_release()
    {
        var repository = ResolveRepository();
        var prestart = File.ReadAllText(Path.Combine(
            repository,
            "helpers/prestart.sh"));
        var bootstrap = File.ReadAllText(Path.Combine(
            repository,
            "helpers/bootstrap-release.sh"));
        var installer = File.ReadAllText(Path.Combine(
            repository,
            "helpers/install.sh"));

        Assert.DoesNotContain("chown -R", prestart, StringComparison.Ordinal);
        Assert.DoesNotContain("openssl req", prestart, StringComparison.Ordinal);
        Assert.DoesNotContain("TestCert", prestart + bootstrap, StringComparison.Ordinal);
        Assert.Contains("openssl rand", bootstrap, StringComparison.Ordinal);
        Assert.Contains("chown -R root:root", bootstrap, StringComparison.Ordinal);
        Assert.Contains(
            "install -o root -g root -m 0755",
            installer,
            StringComparison.Ordinal);
    }

    [Fact]
    public async Task Production_preflight_fails_before_start_when_certificate_is_missing()
    {
        var repository = ResolveRepository();
        var temporaryRoot = Directory.CreateTempSubdirectory("sufficit-identity-prestart-");
        var release = Path.Combine(temporaryRoot.FullName, "release");
        var config = Path.Combine(temporaryRoot.FullName, "config");
        Directory.CreateDirectory(release);
        Directory.CreateDirectory(config);

        try
        {
            var script = Path.Combine(repository, "helpers/prestart.sh");
            using var process = new Process
            {
                StartInfo = new ProcessStartInfo
                {
                    FileName = "/bin/bash",
                    UseShellExecute = false,
                    RedirectStandardError = true,
                    RedirectStandardOutput = true,
                },
            };
            process.StartInfo.ArgumentList.Add(script);
            process.StartInfo.ArgumentList.Add(release);
            process.StartInfo.ArgumentList.Add(config);
            process.StartInfo.Environment["ASPNETCORE_ENVIRONMENT"] = "Production";

            Assert.True(process.Start());
            var error = await process.StandardError.ReadToEndAsync();
            await process.StandardOutput.ReadToEndAsync();
            await process.WaitForExitAsync();

            Assert.NotEqual(0, process.ExitCode);
            Assert.Contains("required", error, StringComparison.OrdinalIgnoreCase);
        }
        finally
        {
            Directory.Delete(temporaryRoot.FullName, recursive: true);
        }
    }

    private static string ResolveRepository()
    {
        var directory = new DirectoryInfo(AppContext.BaseDirectory);
        while (directory is not null)
        {
            if (File.Exists(Path.Combine(directory.FullName, "Sufficit.Identity.sln")))
            {
                return directory.FullName;
            }

            directory = directory.Parent;
        }

        throw new InvalidOperationException("Unable to find repository root.");
    }
}
