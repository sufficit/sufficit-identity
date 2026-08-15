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
        Assert.Contains("certificate*.pfx", bootstrap, StringComparison.Ordinal);
        Assert.Contains("Preserved certificate overlap", bootstrap, StringComparison.Ordinal);
        Assert.Contains("chown -R root:root", bootstrap, StringComparison.Ordinal);
        Assert.Contains(
            "install -o root -g root -m 0755",
            installer,
            StringComparison.Ordinal);
    }

    [Fact]
    public void Cluster_packaging_preserves_runtime_configuration_outside_the_archive()
    {
        var repository = ResolveRepository();
        var package = File.ReadAllText(Path.Combine(
            repository,
            "helpers/package-release.sh"));
        var prepare = File.ReadAllText(Path.Combine(
            repository,
            "helpers/prepare-cluster-release.sh"));
        var activate = File.ReadAllText(Path.Combine(
            repository,
            "helpers/activate-cluster-release.sh"));

        Assert.Contains("Refusing to package a dirty worktree", package, StringComparison.Ordinal);
        Assert.Contains("appsettings*.json", package, StringComparison.Ordinal);
        Assert.Contains("certificate*.pfx", package, StringComparison.Ordinal);
        Assert.Contains("REVISION", package, StringComparison.Ordinal);
        Assert.Contains("-o \"${release_directory}\" >&2", package, StringComparison.Ordinal);
        Assert.Contains("preserve-release-configuration.sh", prepare, StringComparison.Ordinal);
        Assert.Contains("sha256sum -c", prepare, StringComparison.Ordinal);
        Assert.Contains("configuration inherited", prepare, StringComparison.Ordinal);
        Assert.Contains("candidate-configuration-drift", activate, StringComparison.Ordinal);
    }

    [Fact]
    public async Task Candidate_configuration_is_an_exact_copy_of_the_active_release()
    {
        var repository = ResolveRepository();
        var script = Path.Combine(
            repository,
            "helpers/preserve-release-configuration.sh");
        var temporaryRoot = Directory.CreateTempSubdirectory(
            "sufficit-identity-release-config-");
        var releases = Directory.CreateDirectory(Path.Combine(
            temporaryRoot.FullName,
            "releases"));
        var active = Directory.CreateDirectory(Path.Combine(releases.FullName, "active"));
        var candidate = Directory.CreateDirectory(Path.Combine(releases.FullName, "candidate"));

        try
        {
            await File.WriteAllTextAsync(
                Path.Combine(active.FullName, "appsettings.Production.json"),
                "{\"Authority\":\"active-production-value\"}");
            await File.WriteAllTextAsync(
                Path.Combine(active.FullName, "appsettings.test-node.json"),
                "{\"Node\":\"active-machine-value\"}");
            await File.WriteAllTextAsync(
                Path.Combine(candidate.FullName, "appsettings.Production.json"),
                "{\"Authority\":\"stale-value\"}");
            await File.WriteAllTextAsync(
                Path.Combine(candidate.FullName, "appsettings.obsolete.json"),
                "{\"Obsolete\":true}");

            var result = await RunScriptAsync(
                script,
                [active.FullName, candidate.FullName, "test-node"],
                new Dictionary<string, string?>
                {
                    ["IDENTITY_RELEASES_ROOT"] = releases.FullName,
                });

            Assert.Equal(0, result.ExitCode);
            Assert.Equal(
                await File.ReadAllTextAsync(Path.Combine(
                    active.FullName,
                    "appsettings.Production.json")),
                await File.ReadAllTextAsync(Path.Combine(
                    candidate.FullName,
                    "appsettings.Production.json")));
            Assert.Equal(
                await File.ReadAllTextAsync(Path.Combine(
                    active.FullName,
                    "appsettings.test-node.json")),
                await File.ReadAllTextAsync(Path.Combine(
                    candidate.FullName,
                    "appsettings.test-node.json")));
            Assert.False(File.Exists(Path.Combine(
                candidate.FullName,
                "appsettings.obsolete.json")));
            Assert.DoesNotContain("active-production-value", result.Output, StringComparison.Ordinal);
            Assert.DoesNotContain("active-machine-value", result.Output, StringComparison.Ordinal);
        }
        finally
        {
            temporaryRoot.Delete(recursive: true);
        }
    }

    [Fact]
    public async Task Missing_machine_configuration_fails_before_candidate_is_changed()
    {
        var repository = ResolveRepository();
        var script = Path.Combine(
            repository,
            "helpers/preserve-release-configuration.sh");
        var temporaryRoot = Directory.CreateTempSubdirectory(
            "sufficit-identity-release-config-failure-");
        var releases = Directory.CreateDirectory(Path.Combine(
            temporaryRoot.FullName,
            "releases"));
        var active = Directory.CreateDirectory(Path.Combine(releases.FullName, "active"));
        var candidate = Directory.CreateDirectory(Path.Combine(releases.FullName, "candidate"));
        var candidateConfiguration = Path.Combine(
            candidate.FullName,
            "appsettings.Production.json");

        try
        {
            await File.WriteAllTextAsync(
                Path.Combine(active.FullName, "appsettings.Production.json"),
                "{\"Authority\":\"active\"}");
            await File.WriteAllTextAsync(candidateConfiguration, "{\"Candidate\":\"unchanged\"}");

            var result = await RunScriptAsync(
                script,
                [active.FullName, candidate.FullName, "missing-node"],
                new Dictionary<string, string?>
                {
                    ["IDENTITY_RELEASES_ROOT"] = releases.FullName,
                });

            Assert.NotEqual(0, result.ExitCode);
            Assert.Contains(
                "Required active configuration is missing",
                result.Error,
                StringComparison.Ordinal);
            Assert.Equal(
                "{\"Candidate\":\"unchanged\"}",
                await File.ReadAllTextAsync(candidateConfiguration));
        }
        finally
        {
            temporaryRoot.Delete(recursive: true);
        }
    }

    [Fact]
    public async Task Vault_environment_file_is_wired_and_checked_without_echoing_values()
    {
        var repository = ResolveRepository();
        var service = File.ReadAllText(Path.Combine(
            repository,
            "helpers/sufficit-identity.service"));
        var migratorService = File.ReadAllText(Path.Combine(
            repository,
            "helpers/sufficit-identity-migrator.service"));
        var localServicePath = Path.Combine(
            repository,
            "deploy/local/systemd/sufficit-identity.service");
        var installer = File.ReadAllText(Path.Combine(repository, "helpers/install.sh"));
        var template = File.ReadAllText(Path.Combine(
            repository,
            "helpers/vault-secrets.env.template"));
        var checker = Path.Combine(repository, "helpers/check-vault-secrets.sh");
        var checkerSource = File.ReadAllText(checker);
        var hardeningTemplate = File.ReadAllText(Path.Combine(
            repository,
            "helpers/hardening.env.template"));

        Assert.Contains(
            "EnvironmentFile=-/etc/sufficit/identity/vault-secrets.env",
            service,
            StringComparison.Ordinal);
        Assert.Contains(
            "EnvironmentFile=-/etc/sufficit/identity/vault-secrets.env",
            migratorService,
            StringComparison.Ordinal);
        if (File.Exists(localServicePath))
        {
            var localService = File.ReadAllText(localServicePath);
            Assert.Contains(
                "EnvironmentFile=-/etc/sufficit/identity/vault-secrets.env",
                localService,
                StringComparison.Ordinal);
        }
        Assert.Contains("vault-secrets.env", installer, StringComparison.Ordinal);
        Assert.Contains("check-vault-secrets.sh", installer, StringComparison.Ordinal);
        Assert.Contains(
            "SUFFICIT_SECRET_DATABASE_CONNECTION_STRING",
            template,
            StringComparison.Ordinal);
        Assert.Contains(
            "SUFFICIT_SECRET_VAULT_KEK_CERTIFICATE_PASSWORD",
            template,
            StringComparison.Ordinal);
        Assert.Contains(
            "SUFFICIT_SECRET_VAULT_KEK_CERTIFICATE_PASSWORD",
            checkerSource,
            StringComparison.Ordinal);
        Assert.DoesNotContain("echo \"${value}\"", checkerSource, StringComparison.Ordinal);
        // The tenant mapping seed was removed with the multi-tenant system
        // (2026-08 decision); the template must not reintroduce it.
        Assert.DoesNotContain(
            "TenantAccess__SubjectTenants",
            hardeningTemplate,
            StringComparison.Ordinal);

        var temporaryRoot = Directory.CreateTempSubdirectory("sufficit-identity-vault-env-");
        try
        {
            var validFile = Path.Combine(temporaryRoot.FullName, "valid.env");
            await File.WriteAllTextAsync(
                validFile,
                "# test-only value\n"
                + "SUFFICIT_SECRET_DATABASE_CONNECTION_STRING=test-value\n"
                + "SUFFICIT_SECRET_VAULT_KEK_CERTIFICATE_PASSWORD=vault-test-value\n");
            var valid = await RunScriptAsync(checker, validFile);

            Assert.Equal(0, valid.ExitCode);
            Assert.Contains("2 configured entries", valid.Output, StringComparison.Ordinal);
            Assert.DoesNotContain("test-value", valid.Output, StringComparison.Ordinal);
            Assert.DoesNotContain("vault-test-value", valid.Output, StringComparison.Ordinal);

            var invalidFile = Path.Combine(temporaryRoot.FullName, "invalid.env");
            await File.WriteAllTextAsync(invalidFile, "UNSUPPORTED_SECRET=test-value\n");
            var invalid = await RunScriptAsync(checker, invalidFile);

            Assert.NotEqual(0, invalid.ExitCode);
            Assert.Contains("Unsupported secret environment key", invalid.Error, StringComparison.Ordinal);
            Assert.DoesNotContain("test-value", invalid.Output + invalid.Error, StringComparison.Ordinal);
        }
        finally
        {
            Directory.Delete(temporaryRoot.FullName, recursive: true);
        }
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

    private static async Task<(int ExitCode, string Output, string Error)> RunScriptAsync(
        string script,
        string configFile)
        => await RunScriptAsync(script, [configFile]);

    private static async Task<(int ExitCode, string Output, string Error)> RunScriptAsync(
        string script,
        IReadOnlyList<string> arguments,
        IReadOnlyDictionary<string, string?>? environment = null)
    {
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
        foreach (var argument in arguments)
        {
            process.StartInfo.ArgumentList.Add(argument);
        }
        if (environment is not null)
        {
            foreach (var (name, value) in environment)
            {
                process.StartInfo.Environment[name] = value;
            }
        }

        Assert.True(process.Start());
        var outputTask = process.StandardOutput.ReadToEndAsync();
        var errorTask = process.StandardError.ReadToEndAsync();
        await process.WaitForExitAsync();

        return (process.ExitCode, await outputTask, await errorTask);
    }
}
