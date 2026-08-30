using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Security.Claims;
using System.Text.Json;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.Extensions.Caching.Distributed;
using Microsoft.AspNetCore.WebUtilities;
using Microsoft.Extensions.Configuration;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;
using Sufficit.Identity.Core.Entities;
using Sufficit.Identity.Core.Data;
using Sufficit.Identity.Tests.Infrastructure;
using Sufficit.Identity.Management.Provisioning;
using Sufficit.Identity.Management;
using Sufficit.Identity.Management.Authorization;
using Sufficit.Identity.Management.Vault;
using Sufficit.Identity.STS;
using Sufficit.Identity.STS.Email;
using Sufficit.Identity.STS.Vault;
using Sufficit.Identity.Vault;
using Sufficit.Identity.Vault.Crypto;
using Xunit;

namespace Sufficit.Identity.Tests;

public sealed partial class VaultTests
{
    [Fact]
    public void Registration_exposes_the_configured_state_through_options()
    {
        var configuration = new ConfigurationBuilder()
            .AddInMemoryCollection(new Dictionary<string, string?>
            {
                ["ASPNETCORE_ENVIRONMENT"] = "Development",
                [$"{VaultOptions.SectionName}:Enabled"] = "true",
                [$"{VaultOptions.SectionName}:KeySource"] = "dataprotection"
            })
            .Build();
        var services = new ServiceCollection();

        services.AddSufficitVault(configuration);

        using var provider = services.BuildServiceProvider();
        var configured = provider.GetRequiredService<IOptions<VaultOptions>>().Value;
        Assert.True(configured.Enabled);
        Assert.Equal("dataprotection", configured.KeySource);
        Assert.Contains(
            services,
            descriptor => descriptor.ServiceType == typeof(IUserVaultOverviewService)
                && descriptor.ImplementationType == typeof(UserVaultOverviewService));
    }

    [Fact]
    public void Encryption_is_required_by_default_and_cannot_be_disabled_outside_development()
    {
        var defaults = new VaultOptions();
#pragma warning disable CS0618
        Assert.True(defaults.RequireEncryptionInProduction);
        var legacyOverride = new VaultOptions
        {
            Enabled = false,
            RequireEncryptionInProduction = false,
        };
#pragma warning restore CS0618

        var exception = Assert.Throws<InvalidOperationException>(() =>
            Sufficit.Identity.Vault.ServiceCollectionExtensions.ValidateRuntimeMode(
                legacyOverride,
                isDevelopment: false));
        Assert.Contains("development-only", exception.Message,
            StringComparison.Ordinal);

        Sufficit.Identity.Vault.ServiceCollectionExtensions.ValidateRuntimeMode(
            new VaultOptions { Enabled = false },
            isDevelopment: true);
    }

    [Fact]
    public void Production_kek_policy_requires_dedicated_certificate_and_rejects_token_signing_reuse()
    {
        var emptyConfiguration = new ConfigurationBuilder().Build();
        var dataProtection = Assert.Throws<InvalidOperationException>(() =>
            Sufficit.Identity.Vault.ServiceCollectionExtensions
                .ValidateKeyEncryptionKeyPolicy(
                    new VaultOptions
                    {
                        Enabled = true,
                        KeySource = "dataprotection",
                    },
                    emptyConfiguration,
                    isDevelopment: false));
        Assert.Contains("certificate", dataProtection.Message,
            StringComparison.OrdinalIgnoreCase);

        var sharedPath = Path.GetFullPath("shared-signing-and-kek.pfx");
        var sharedConfiguration = new ConfigurationBuilder()
            .AddInMemoryCollection(new Dictionary<string, string?>
            {
                ["Sufficit:Identity:Certificates:SigningPath"] = sharedPath,
            })
            .Build();
        var reuse = Assert.Throws<InvalidOperationException>(() =>
            Sufficit.Identity.Vault.ServiceCollectionExtensions
                .ValidateKeyEncryptionKeyPolicy(
                    new VaultOptions
                    {
                        Enabled = true,
                        KeySource = "certificate",
                        CertificatePath = sharedPath,
                    },
                    sharedConfiguration,
                    isDevelopment: false));
        Assert.Contains("different", reuse.Message, StringComparison.Ordinal);
    }

    [Fact]
    public void External_kms_adapter_pins_identifier_and_round_trips()
    {
        var provider = new XorExternalKeyEncryptionProvider("kms://test/kek/7");
        var source = new ExternalKeySource(provider, new VaultOptions
        {
            ExternalKeyIdentifier = "kms://test/kek/7",
        });
        var plaintext = RandomNumberGenerator.GetBytes(32);

        Assert.Equal(plaintext, source.Unwrap(source.Wrap(plaintext)));
        Assert.Throws<InvalidOperationException>(() =>
            new ExternalKeySource(provider, new VaultOptions
            {
                ExternalKeyIdentifier = "kms://test/kek/8",
            }));
    }

    [Fact]
    public void Legacy_data_protection_certificate_fallback_is_bounded_and_attributed()
    {
        var now = new DateTimeOffset(2026, 8, 9, 12, 0, 0, TimeSpan.Zero);
        Assert.Throws<InvalidOperationException>(() =>
            Sufficit.Identity.Vault.ServiceCollectionExtensions
                .ValidateLegacyCertificateMigration(
                    new VaultLegacyCertificateMigrationOptions
                    {
                        Owner = "identity-platform",
                        ExpiresAtUtc = now.AddDays(30),
                    },
                    now));
        Assert.Throws<InvalidOperationException>(() =>
            Sufficit.Identity.Vault.ServiceCollectionExtensions
                .ValidateLegacyCertificateMigration(
                    new VaultLegacyCertificateMigrationOptions
                    {
                        Owner = "identity-platform",
                        Reason = "rotate the legacy DP ring",
                        ExpiresAtUtc = now,
                    },
                    now));

        Sufficit.Identity.Vault.ServiceCollectionExtensions
            .ValidateLegacyCertificateMigration(
                new VaultLegacyCertificateMigrationOptions
                {
                    Owner = "identity-platform",
                    Reason = "rotate the legacy DP ring",
                    ExpiresAtUtc = now.AddDays(30),
                },
                now);
    }

    [Fact]
    public async Task Registration_does_not_read_configuration_as_secret()
    {
        var configuration = new ConfigurationBuilder()
            .AddInMemoryCollection(new Dictionary<string, string?>
            {
                ["ASPNETCORE_ENVIRONMENT"] = "Development",
                [$"{VaultOptions.SectionName}:Enabled"] = "true",
                ["Secrets:database/password"] = "configured-secret",
            })
            .Build();
        var services = new ServiceCollection();
        services.AddSufficitVault(configuration);

        using var provider = services.BuildServiceProvider();
        var store = provider.GetRequiredService<ISecretStore>();

        Assert.Null(
            await store.GetSecretAsync("database/password"));
    }

    [Fact]
    public void Startup_secret_overrides_take_precedence_without_logging_values()
    {
        const string environmentName =
            "SUFFICIT_SECRET_IDENTITY_CERTIFICATES_SIGNING_PASSWORD";
        var previous = Environment.GetEnvironmentVariable(environmentName);
        try
        {
            Environment.SetEnvironmentVariable(environmentName, "from-environment");
            var configuration = new ConfigurationBuilder()
                .AddInMemoryCollection(new Dictionary<string, string?>
                {
                    ["Sufficit:Identity:Certificates:SigningPassword"] =
                        "from-json",
                })
                .AddSufficitSecretOverrides()
                .Build();

            Assert.Equal(
                "from-environment",
                configuration["Sufficit:Identity:Certificates:SigningPassword"]);
        }
        finally
        {
            Environment.SetEnvironmentVariable(environmentName, previous);
        }
    }

    [Fact]
    public async Task Environment_secret_store_ignores_legacy_startup_configuration()
    {
        var store = new EnvironmentSecretStore();

        Assert.Null(
            await store.GetSecretAsync(
                "identity/certificates/signing-password"));
    }

    [Fact]
    public void Plaintext_startup_secrets_are_rejected_before_environment_overrides()
    {
        var configuration = new ConfigurationBuilder()
            .AddInMemoryCollection(new Dictionary<string, string?>
            {
                ["Sufficit:Identity:Certificates:SigningPassword"] =
                    "legacy-signing-password",
            })
            .Build();

        var exception = Assert.Throws<InvalidOperationException>(
            () => SecretConfigurationExtensions.EnsureNoPlaintextSecrets(
                configuration));

        Assert.Contains("SigningPassword", exception.Message, StringComparison.Ordinal);
        Assert.DoesNotContain("legacy-signing-password", exception.Message, StringComparison.Ordinal);
    }

    [Fact]
    public void Email_transports_resolve_passwords_from_the_secret_store()
    {
        var configuration = new ConfigurationBuilder()
            .AddInMemoryCollection(new Dictionary<string, string?>
            {
                ["Sufficit:Exchange:RabbitMQ:HostName"] = "broker",
                ["Sufficit:Exchange:RabbitMQ:Password"] = "legacy-rabbit",
                ["Sufficit:Identity:Smtp:Password"] = "legacy-smtp",
            })
            .Build();
        var store = new DictionarySecretStore(new Dictionary<string, string?>
        {
            ["exchange/rabbitmq/password"] = "store-rabbit",
            ["identity/smtp/password"] = "store-smtp",
        });
        var services = new ServiceCollection();
        services.AddLogging();
        services.AddSufficitEmailSender(configuration, store);

        using var provider = services.BuildServiceProvider();
        var rabbit = provider.GetRequiredService<IOptions<RabbitMqEmailOptions>>().Value;

        Assert.Equal("store-rabbit", rabbit.Password);
        Assert.Contains("exchange/rabbitmq/password", store.RequestedNames);
    }

    [Fact]
    public void Startup_secret_overrides_can_be_resolved_through_ISecretStore()
    {
        var store = new DictionarySecretStore(new Dictionary<string, string?>
        {
            ["database/connection-string"] = "server=secret-host;database=identity",
            ["identity/certificates/signing-password"] = "signing-secret",
        });
        var configuration = new ConfigurationBuilder()
            .AddSufficitSecretOverrides(store)
            .Build();

        Assert.Equal(
            "server=secret-host;database=identity",
            configuration["ConnectionStrings:DefaultConnection"]);
        Assert.Equal(
            "signing-secret",
            configuration["Sufficit:Identity:Certificates:SigningPassword"]);
        Assert.Null(configuration["Sufficit:Identity:Certificates:EncryptionPassword"]);
        Assert.Equal(
            SecretConfigurationExtensions.GetSufficitSecretOverrideMappings().Count,
            store.RequestedNames.Count);
        Assert.Contains("database/connection-string", store.RequestedNames);
        Assert.Contains("identity/certificates/signing-password", store.RequestedNames);
    }
}
