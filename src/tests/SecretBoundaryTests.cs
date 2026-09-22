using Microsoft.Extensions.Configuration;
using Sufficit.Identity.Application.Security;
using Sufficit.Identity.Vault;
using Xunit;

namespace Sufficit.Identity.Tests;

public sealed class SecretBoundaryTests
{
    private static IConfigurationRoot Configuration(
        params (string Key, string Value)[] values) =>
        new ConfigurationBuilder()
            .AddInMemoryCollection(values.ToDictionary(
                pair => pair.Key,
                pair => (string?)pair.Value))
            .Build();

    private sealed class StubStore(params string[] known) : ISecretStore
    {
        public Task<string?> GetSecretAsync(
            string name,
            CancellationToken cancellationToken = default) =>
            Task.FromResult(known.Contains(name, StringComparer.Ordinal)
                ? "value-that-never-leaves-this-method"
                : null);
    }

    [Fact]
    public void Provenance_distinguishes_the_boundary_from_the_fallback()
    {
        var builder = new ConfigurationBuilder()
            .AddInMemoryCollection(new Dictionary<string, string?>
            {
                // A stale appsettings value: present, and not from the store.
                ["Sufficit:Identity:Smtp:Password"] = "left-behind",
            });

        builder.AddSufficitSecretOverrides(
            new StubStore("database/connection-string"),
            out var report);

        Assert.Equal(
            SecretResolutionSource.SecretStore,
            Source(report, "database/connection-string"));
        Assert.Equal(
            SecretResolutionSource.Configuration,
            Source(report, "identity/smtp/password"));
        Assert.Equal(
            SecretResolutionSource.Absent,
            Source(report, "identity/human-verification/secret-key"));

        Assert.Equal(
            ["identity/smtp/password"],
            report.ConfigurationFallbacks
                .Select(resolution => resolution.LogicalName));

        // The whole point is that provenance is answerable without the value,
        // so nothing that renders the report may carry one.
        Assert.DoesNotContain("left-behind", report.ToString());
        Assert.DoesNotContain(
            "value-that-never-leaves-this-method",
            report.ToString());

        static SecretResolutionSource Source(
            SecretResolutionReport report,
            string logicalName) =>
            report.Resolutions
                .Single(resolution => resolution.LogicalName == logicalName)
                .Source;
    }

    [Fact]
    public void A_declared_migration_turns_a_fallback_into_a_regression()
    {
        var report = new SecretResolutionReport([
            new("identity/smtp/password",
                "Sufficit:Identity:Smtp:Password",
                SecretResolutionSource.Configuration),
        ]);

        // Mid-migration a fallback is the state being migrated out of.
        var during = new SecretBoundaryPostureContributor(
            Configuration(), report).Evaluate().ToArray();
        Assert.Equal(
            ProductionPostureSeverity.Advisory,
            Assert.Single(during, f => f.Id == "secret-configuration-fallback")
                .Severity);

        // Once the deployment says it finished, the next one is a regression
        // and refuses startup, which is the reason to declare it.
        var after = new SecretBoundaryPostureContributor(
            Configuration((
                SecretBoundaryPostureContributor.MigrationCompleteKey, "true")),
            report).Evaluate().ToArray();
        Assert.Equal(
            ProductionPostureSeverity.Blocking,
            Assert.Single(after, f => f.Id == "secret-configuration-fallback")
                .Severity);

        Assert.DoesNotContain(
            new SecretBoundaryPostureContributor(
                Configuration(),
                new SecretResolutionReport([])).Evaluate(),
            f => f.Id == "secret-configuration-fallback");
    }

    [Theory]
    // Credential-looking and unmapped: the gate for the seventeen mapped keys
    // cannot see these at all.
    [InlineData("Sufficit:Identity:ResourceSecret", "abc", true)]
    [InlineData("Sufficit:Partner:ApiKey", "abc", true)]
    // The value carries the credential, whatever the key is called.
    [InlineData("ConnectionStrings:Reporting", "Server=db;Password=x", true)]
    // A switch named after a secret is still a switch.
    [InlineData("Sufficit:Identity:LegacyGrants:Password", "false", false)]
    [InlineData("Sufficit:Identity:Mcp:Dcr:RequireInitialAccessToken", "true", false)]
    // This repository documents a key with a commented twin beside it.
    [InlineData("Sufficit:Identity:_Password", "see vault-secrets.env", false)]
    // Names, paths and lifetimes are settings.
    [InlineData("Sufficit:Partner:ApiKeyName", "x-api-key", false)]
    [InlineData("Sufficit:Vault:SigningKeyName", "oidc-signing", false)]
    // Already mapped, so EnsureNoPlaintextSecrets owns it.
    [InlineData("Sufficit:Identity:Smtp:Password", "abc", false)]
    public void Unmapped_credential_like_keys_are_found_by_convention(
        string key,
        string value,
        bool found)
    {
        var keys = SecretConfigurationExtensions.FindUnmappedSecretLikeKeys(
            Configuration((key, value)));

        Assert.Equal(found, keys.Contains(key));
    }

    [Fact]
    public void The_secret_boundary_variables_are_not_reported_as_being_outside_it()
    {
        // Environment variables are part of the configuration the scan walks,
        // so the values that arrived through the boundary were being reported
        // as having missed it — with the advice to move them to a
        // SUFFICIT_SECRET_* variable, which is what they already were.
        // Production logged ten of these on 2026-09-19.
        var keys = SecretConfigurationExtensions.FindUnmappedSecretLikeKeys(
            Configuration(
                ("SUFFICIT_SECRET_DATABASE_CONNECTION_STRING", "server=db;password=p"),
                ("SUFFICIT_SECRET_IDENTITY_CERTIFICATES_SIGNING_PASSWORD", "p"),
                ("SUFFICIT_SECRET_IDENTITY_EXTERNAL_PROVIDERS_GOOGLE_CLIENT_SECRET", "p")));

        Assert.Empty(keys);
    }

    [Fact]
    public void A_credential_outside_the_boundary_is_still_reported()
    {
        // The exclusion above must not blind the scan: only the prefix is
        // trusted, and a credential sitting anywhere else is still a finding.
        var keys = SecretConfigurationExtensions.FindUnmappedSecretLikeKeys(
            Configuration(
                ("SUFFICIT_SECRET_DATABASE_CONNECTION_STRING", "server=db;password=p"),
                ("Sufficit:Integrations:Acme:ApiSecret", "abc123")));

        Assert.Equal(["Sufficit:Integrations:Acme:ApiSecret"], keys);
    }

    [Fact]
    public void The_secret_store_variables_are_not_reported_as_loose_secrets()
    {
        // Exactly what production reported on 2026-09-19: environment
        // variables are a configuration source, so the SUFFICIT_SECRET_*
        // names appear in configuration like anything else. Reporting them
        // told every correctly-configured deployment the opposite of the
        // truth — these names are the boundary, not a way around it.
        var configuration = Configuration(
            ("SUFFICIT_SECRET_DATABASE_CONNECTION_STRING", "Server=db;Password=x"),
            ("SUFFICIT_SECRET_IDENTITY_CERTIFICATES_SIGNING_PASSWORD", "abc"),
            ("SUFFICIT_SECRET_IDENTITY_EXTERNAL_PROVIDERS_GOOGLE_CLIENT_SECRET", "abc"),
            ("sufficit_secret_lowercase_password", "abc"));

        Assert.Empty(
            SecretConfigurationExtensions.FindUnmappedSecretLikeKeys(configuration));

        // A secret in an environment variable that is not one of those is
        // still outside the table, and still reported.
        Assert.Contains(
            "SOME_OTHER_API_KEY",
            SecretConfigurationExtensions.FindUnmappedSecretLikeKeys(
                Configuration(("SOME_OTHER_API_KEY", "abc"))));

        // And the operational file beside it, which carries settings rather
        // than secrets and spells configuration keys with double underscores.
        Assert.Empty(SecretConfigurationExtensions.FindUnmappedSecretLikeKeys(
            Configuration(
                ("Sufficit:Identity:RateLimit:Enabled", "true"),
                ("Sufficit:Identity:Csp:ReportUri", "/security/csp-report"),
                ("Sufficit:Identity:Management:RequireMfa", "true"),
                ("Sufficit:Vault:CertificatePath", "/etc/sufficit/identity/vault-kek.pfx"),
                ("Sufficit:Identity:Database:ConnectionPool:ApplicationName", "Sufficit.Identity"))));
    }

    [Fact]
    public void The_unmapped_scan_is_quiet_on_this_repository_own_configuration()
    {
        // A scanner that fires on the shipped template is a scanner operators
        // learn to ignore. The template is the closest thing to a realistic
        // configuration this repository can assert against.
        var template = Path.Combine(
            RepositoryRoot(),
            "src",
            "server",
            "appsettings.json.template");
        Assert.True(File.Exists(template), template);

        Assert.Empty(SecretConfigurationExtensions.FindUnmappedSecretLikeKeys(
            new ConfigurationBuilder().AddJsonFile(template).Build()));
    }

    private static string RepositoryRoot()
    {
        var directory = new DirectoryInfo(AppContext.BaseDirectory);
        while (directory is not null
            && !Directory.Exists(Path.Combine(directory.FullName, ".git"))
            && !File.Exists(Path.Combine(directory.FullName, ".git")))
        {
            directory = directory.Parent;
        }

        Assert.NotNull(directory);
        return directory.FullName;
    }
}
