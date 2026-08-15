using Microsoft.Extensions.Caching.Distributed;
using Microsoft.Extensions.Caching.Memory;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;
using Sufficit.Identity.Application.Security;
using Sufficit.Identity.Management;
using Sufficit.Identity.Management.Authorization;
using Sufficit.Identity.Scim;
using Sufficit.Identity.STS;
using Sufficit.Identity.STS.Grants;
using Sufficit.Identity.STS.Controllers;
using Sufficit.Identity.STS.Security;
using Sufficit.Identity.Vault;
using Xunit;
using ManagementLayerOptions = Sufficit.Identity.Management.ManagementOptions;

namespace Sufficit.Identity.Tests;

public sealed class ProductionPostureCheckTests
{
    private static readonly DateTimeOffset Now =
        new(2026, 8, 9, 12, 0, 0, TimeSpan.Zero);

    [Fact]
    public void Security_sensitive_policy_defaults_are_enforced()
    {
        Assert.Equal(
            PublicOriginMode.Enforce,
            new PublicOriginPolicyOptions().Mode);
        Assert.Equal(
            CredentialMutationStepUpMode.Enforce,
            new CredentialMutationSecurityOptions().StepUpMode);
        Assert.Equal(
            SecurityPolicyEnforcementMode.Enforce,
            new PersonalTokenIssuanceOptions().Mode);
        Assert.Equal(
            SecurityPolicyEnforcementMode.Enforce,
            new CibaOptions().ClientPolicyMode);
        Assert.Equal(
            SecurityPolicyEnforcementMode.Enforce,
            new TokenExchangeOptions().ProvenanceMode);
        Assert.Equal(
            ManagementPolicyEnforcementMode.Enforce,
            new ProtectedPrincipalAccessOptions().Mode);
        Assert.Equal(
            ScimClientPolicyMode.Enforce,
            new ScimOptions().ClientPolicyMode);
    }

    [Fact]
    public void Contract_covers_every_known_permissive_production_switch()
    {
        var root = new SufficitIdentityOptions
        {
            Csp = new CspOptions { Enabled = true, ReportOnly = true },
            PersonalTokens = new PersonalTokenIssuanceOptions
            {
                Mode = SecurityPolicyEnforcementMode.Observe,
            },
            Ciba = new CibaOptions
            {
                Enabled = true,
                ClientPolicyMode = SecurityPolicyEnforcementMode.Observe,
            },
            CredentialMutations = new CredentialMutationSecurityOptions
            {
                StepUpMode = CredentialMutationStepUpMode.Audit,
            },
            PublicOrigin = new PublicOriginPolicyOptions
            {
                Mode = PublicOriginMode.Audit,
            },
            Dpop = new DpopOptions { Enabled = true },
            DistributedCache = new DistributedCacheOptions
            {
                RequireShared = true,
            },
        };
        var configuration = new ConfigurationBuilder()
            .AddInMemoryCollection(new Dictionary<string, string?>
            {
                ["Sufficit:Identity:TokenExchange:Enabled"] = "true",
                ["Sufficit:Identity:TokenExchange:AllowedClientIds:0"] = "exchange-client",
                ["Sufficit:Identity:TokenExchange:ProvenanceMode"] = "Observe",
            })
            .Build();
        var cache = new MemoryDistributedCache(
            Options.Create(new MemoryDistributedCacheOptions()));
        var management = new ManagementLayerOptions
        {
            Enabled = true,
            RequireAuthorization = false,
            Authorization = new ManagementAuthorizationOptions
            {
                ProtectedPrincipals = new ProtectedPrincipalAccessOptions
                {
                    Mode = ManagementPolicyEnforcementMode.Observe,
                },
            },
        };
        var scim = new ScimOptions
        {
            Enabled = true,
            RequireAllowedClient = true,
            ClientPolicyMode = ScimClientPolicyMode.Observe,
        };

        var findings = Evaluate(
            new StsProductionPostureContributor(root, configuration, cache),
            new ManagementProductionPostureContributor(Options.Create(management)),
            new ScimProductionPostureContributor(Options.Create(scim)),
            new VaultProductionPostureContributor(new VaultOptions()));

        var expected = new HashSet<string>(StringComparer.Ordinal)
        {
            "csp-report-only",
            "personal-tokens-observe",
            "token-exchange-provenance-observe",
            "ciba-client-policy-observe",
            "credential-mutations-step-up-audit",
            "public-origin-request-derived",
            "dpop-replay-cache-not-shared",
            "management-authorization-disabled",
            "management-protected-principal-observe",
            "scim-client-policy-observe",
            "vault-plaintext-compatibility",
        };

        Assert.Equal(expected, findings.Select(finding => finding.Id).ToHashSet());
    }

    [Fact]
    public void Scim_disabled_allow_list_is_a_distinct_finding()
    {
        var contributor = new ScimProductionPostureContributor(
            Options.Create(new ScimOptions
            {
                Enabled = true,
                RequireAllowedClient = false,
            }));

        var finding = Assert.Single(Evaluate(contributor));
        Assert.Equal("scim-client-allow-list-disabled", finding.Id);
    }

    [Fact]
    public void Enabled_scim_without_mfa_is_a_distinct_finding()
    {
        var contributor = new ScimProductionPostureContributor(
            Options.Create(new ScimOptions
            {
                Enabled = true,
                RequireMfa = false,
            }));

        Assert.Contains(
            Evaluate(contributor),
            finding => finding.Id == "scim-mfa-disabled");
    }

    [Fact]
    public void Valid_structured_acknowledgement_suppresses_one_finding()
    {
        var options = new SecurityPostureOptions
        {
            Acknowledgements = new Dictionary<string, ProductionPostureAcknowledgement>(
                StringComparer.Ordinal)
            {
                ["test-finding"] = new()
                {
                    Owner = "identity-team",
                    Reason = "bounded migration",
                    ExpiresAtUtc = Now.AddDays(7),
                },
            },
        };

        var findings = ProductionPostureCheck.Evaluate(
            [new StubContributor(new ProductionPostureFinding("test-finding", "summary", "remedy"))],
            options,
            Now);

        Assert.Empty(findings);
    }

    [Theory]
    [InlineData(false, "")]
    [InlineData(true, "")]
    [InlineData(true, "owner")]
    public void Invalid_or_expired_acknowledgement_does_not_suppress(
        bool futureExpiry,
        string owner)
    {
        var options = new SecurityPostureOptions
        {
            Acknowledgements = new Dictionary<string, ProductionPostureAcknowledgement>(
                StringComparer.Ordinal)
            {
                ["test-finding"] = new()
                {
                    Owner = owner,
                    Reason = owner.Length == 0 ? string.Empty : "reason",
                    ExpiresAtUtc = futureExpiry ? Now.AddDays(1) : Now.AddMinutes(-1),
                },
            },
        };

        var findings = ProductionPostureCheck.Evaluate(
            [new StubContributor(new ProductionPostureFinding("test-finding", "summary", "remedy"))],
            options,
            Now);

        if (futureExpiry && owner == "owner")
        {
            Assert.Empty(findings);
        }
        else
        {
            Assert.Equal("test-finding", Assert.Single(findings).Id);
        }
    }

    [Fact]
    public void Stale_acknowledgement_is_a_finding()
    {
        var options = new SecurityPostureOptions
        {
            Acknowledgements = new Dictionary<string, ProductionPostureAcknowledgement>(
                StringComparer.Ordinal)
            {
                ["removed-finding"] = new()
                {
                    Owner = "identity-team",
                    Reason = "old rollout",
                    ExpiresAtUtc = Now.AddDays(1),
                },
            },
        };

        var finding = Assert.Single(ProductionPostureCheck.Evaluate(
            [], options, Now));
        Assert.Equal("stale-acknowledgement:removed-finding", finding.Id);
    }

    [Fact]
    public void Legacy_boolean_acknowledgement_requires_explicit_bridge()
    {
        var contributor = new StubContributor(
            new ProductionPostureFinding(
                "legacy-finding",
                "summary",
                "remedy",
                LegacyAcknowledged: true));

        Assert.Single(ProductionPostureCheck.Evaluate(
            [contributor], new SecurityPostureOptions(), Now));
        Assert.Empty(ProductionPostureCheck.Evaluate(
            [contributor],
            new SecurityPostureOptions
            {
                AllowLegacyBooleanAcknowledgements = true,
            },
            Now));
    }

    [Fact]
    public void Duplicate_finding_ids_fail_closed()
    {
        var contributors = new IProductionPostureContributor[]
        {
            new StubContributor(new ProductionPostureFinding("duplicate", "one", "remedy")),
            new StubContributor(new ProductionPostureFinding("duplicate", "two", "remedy")),
        };

        Assert.Throws<InvalidOperationException>(() =>
            ProductionPostureCheck.Evaluate(
                contributors,
                new SecurityPostureOptions(),
                Now));
    }

    [Fact]
    public void Hardened_configuration_has_no_findings()
    {
        var root = new SufficitIdentityOptions
        {
            PublicUrl = "https://identity.example.com",
            Csp = new CspOptions { Enabled = true, ReportOnly = false },
            PersonalTokens = new PersonalTokenIssuanceOptions
            {
                Mode = SecurityPolicyEnforcementMode.Enforce,
            },
            CredentialMutations = new CredentialMutationSecurityOptions
            {
                StepUpMode = CredentialMutationStepUpMode.Enforce,
            },
        };
        var configuration = new ConfigurationBuilder().Build();
        var management = new ManagementLayerOptions
        {
            Enabled = true,
            RequireAuthorization = true,
            Authorization = new ManagementAuthorizationOptions
            {
                ProtectedPrincipals = new ProtectedPrincipalAccessOptions
                {
                    Mode = ManagementPolicyEnforcementMode.Enforce,
                },
            },
        };
        var scim = new ScimOptions
        {
            Enabled = true,
            RequireAllowedClient = true,
            ClientPolicyMode = ScimClientPolicyMode.Enforce,
        };
        var vault = new VaultOptions { Enabled = true };

        Assert.Empty(Evaluate(
            new StsProductionPostureContributor(root, configuration),
            new ManagementProductionPostureContributor(Options.Create(management)),
            new ScimProductionPostureContributor(Options.Create(scim)),
            new VaultProductionPostureContributor(vault)));
    }

    [Fact]
    public void Non_development_always_fails_closed_even_when_legacy_global_option_is_false()
    {
        var services = new ServiceCollection();
        services.AddSingleton<IProductionPostureContributor>(
            new StubContributor(new ProductionPostureFinding("unresolved", "summary", "remedy")));
        using var provider = services.BuildServiceProvider();
        var options = new SufficitIdentityOptions
        {
#pragma warning disable CS0618
            Security = new SecurityPostureOptions
            {
                FailClosedOnInsecureDefaults = false,
            },
#pragma warning restore CS0618
        };

        Assert.Throws<ProductionPostureException>(() =>
            ProductionPostureCheck.Enforce(
                provider,
                options,
                isDevelopment: false,
                NullLogger.Instance,
                new FixedTimeProvider(Now)));
    }

    [Fact]
    public void Development_logs_but_does_not_throw()
    {
        var services = new ServiceCollection();
        services.AddSingleton<IProductionPostureContributor>(
            new StubContributor(new ProductionPostureFinding("unresolved", "summary", "remedy")));
        using var provider = services.BuildServiceProvider();

        ProductionPostureCheck.Enforce(
            provider,
            new SufficitIdentityOptions(),
            isDevelopment: true,
            NullLogger.Instance,
            new FixedTimeProvider(Now));
    }

    private static IReadOnlyList<ProductionPostureFinding> Evaluate(
        params IProductionPostureContributor[] contributors) =>
        ProductionPostureCheck.Evaluate(
            contributors,
            new SecurityPostureOptions(),
            Now);

    private sealed class StubContributor(params ProductionPostureFinding[] findings)
        : IProductionPostureContributor
    {
        public IEnumerable<ProductionPostureFinding> Evaluate() => findings;
    }

    private sealed class FixedTimeProvider(DateTimeOffset now) : TimeProvider
    {
        public override DateTimeOffset GetUtcNow() => now;
    }
}
