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
            // The fixture's configuration declares no DeploymentTopology, which
            // is exactly the state F-4 makes visible (eval 2026-08-30).
            "deployment-topology-undeclared",
            "management-authorization-disabled",
            "management-protected-principal-observe",
            "scim-client-policy-observe",
            "vault-plaintext-compatibility",
        };

        Assert.Equal(expected, findings.Select(finding => finding.Id).ToHashSet());
    }

    [Theory]
    [InlineData("SingleReplica")]
    [InlineData("Clustered")]
    [InlineData("BehindTrustedProxy")]
    [InlineData("ClusteredBehindTrustedProxy")]
    public void Declared_deployment_topology_clears_the_undeclared_finding(
        string topology)
    {
        // F-4 (eval 2026-08-30): the finding is about the DECLARATION, not the
        // value — even SingleReplica clears it, because the point is that the
        // deployment stated its shape instead of backing into the default.
        var configuration = new ConfigurationBuilder()
            .AddInMemoryCollection(new Dictionary<string, string?>
            {
                ["Sufficit:Identity:DeploymentTopology"] = topology,
            })
            .Build();

        var findings = new StsProductionPostureContributor(
            new SufficitIdentityOptions
            {
                PublicUrl = "https://identity.example.com",
                Csp = new CspOptions { Enabled = true, ReportOnly = false },
            },
            configuration).Evaluate();

        Assert.DoesNotContain(
            findings,
            finding => finding.Id == "deployment-topology-undeclared");
    }

    [Fact]
    public void Undeclared_deployment_topology_is_reported()
    {
        var findings = new StsProductionPostureContributor(
            new SufficitIdentityOptions
            {
                PublicUrl = "https://identity.example.com",
                Csp = new CspOptions { Enabled = true, ReportOnly = false },
            },
            new ConfigurationBuilder().Build()).Evaluate();

        Assert.Contains(
            findings,
            finding => finding.Id == "deployment-topology-undeclared");
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
    public void Enabled_scim_with_an_empty_allow_list_is_reported_without_blocking()
    {
        IReadOnlyList<ProductionPostureFinding> Advisories(ScimOptions scim) =>
            ProductionPostureCheck.EvaluateAdvisories(
                [new ScimProductionPostureContributor(Options.Create(scim))],
                new SecurityPostureOptions(),
                Now);

        // Fail-closed, so nothing to block on — but SCIM turned on and
        // unusable should be visible here rather than only as 403s at the
        // provisioning client.
        var empty = new ScimOptions
        {
            Enabled = true,
            RequireAllowedClient = true,
            ClientPolicyMode = ScimClientPolicyMode.Enforce,
            AllowedClientIds = ["  "],
        };
        Assert.Contains(Advisories(empty), f => f.Id == "scim-client-allow-list-empty");
        Assert.DoesNotContain(
            Evaluate(new ScimProductionPostureContributor(Options.Create(empty))),
            f => f.Id == "scim-client-allow-list-empty");

        Assert.DoesNotContain(
            Advisories(new ScimOptions
            {
                Enabled = true,
                RequireAllowedClient = true,
                AllowedClientIds = ["provisioning"],
            }),
            f => f.Id == "scim-client-allow-list-empty");

        // Disabled SCIM has nothing to report.
        Assert.DoesNotContain(
            Advisories(new ScimOptions { Enabled = false }),
            f => f.Id == "scim-client-allow-list-empty");
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
        // A hardened deployment states its shape rather than inheriting
        // SingleReplica silently (eval 2026-08-30, F-4).
        var configuration = new ConfigurationBuilder()
            .AddInMemoryCollection(new Dictionary<string, string?>
            {
                ["Sufficit:Identity:DeploymentTopology"] = "SingleReplica",
            })
            .Build();
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

    [Fact]
    public void Advisories_are_reported_but_never_block_startup()
    {
        var advisory = new ProductionPostureFinding(
            "advisory-only", "summary", "remedy", Severity: ProductionPostureSeverity.Advisory);
        var vault = new VaultOptions { Enabled = true };

        Assert.Empty(ProductionPostureCheck.Evaluate(
            [new StubContributor(advisory), new VaultProductionPostureContributor(vault)],
            new SecurityPostureOptions(),
            Now));

        var reported = ProductionPostureCheck.EvaluateAdvisories(
                [
                    new StsProductionPostureContributor(
                        new SufficitIdentityOptions(),
                        new ConfigurationBuilder().Build()),
                    new VaultProductionPostureContributor(vault),
                ],
                new SecurityPostureOptions(),
                Now)
            .Select(finding => finding.Id)
            .ToHashSet();
        Assert.Contains("password-breach-check-disabled", reported);
        Assert.Contains("vault-kek-in-data-protection", reported);

        var services = new ServiceCollection();
        services.AddSingleton<IProductionPostureContributor>(new StubContributor(advisory));
        using var provider = services.BuildServiceProvider();
        ProductionPostureCheck.Enforce(
            provider,
            new SufficitIdentityOptions(),
            isDevelopment: false,
            NullLogger.Instance,
            new FixedTimeProvider(Now));
    }

    [Fact]
    public void Acknowledged_advisory_is_silenced_and_not_stale()
    {
        var options = new SecurityPostureOptions
        {
            Acknowledgements = new Dictionary<string, ProductionPostureAcknowledgement>(
                StringComparer.Ordinal)
            {
                ["advisory-only"] = new()
                {
                    Owner = "identity-team",
                    Reason = "accepted risk",
                    ExpiresAtUtc = Now.AddDays(30),
                },
            },
        };
        IProductionPostureContributor[] contributors =
        [
            new StubContributor(new ProductionPostureFinding(
                "advisory-only", "summary", "remedy", Severity: ProductionPostureSeverity.Advisory)),
        ];

        Assert.Empty(ProductionPostureCheck.EvaluateAdvisories(contributors, options, Now));
        Assert.Empty(ProductionPostureCheck.Evaluate(contributors, options, Now));
    }

    [Fact]
    public void Certificate_key_source_and_enabled_breach_check_fail_closed_have_no_advisories()
    {
        var root = new SufficitIdentityOptions
        {
            Password = new PasswordPolicyOptions
            {
                RejectBreached = true,
                BreachedCheckFailureMode = BreachedPasswordFailureMode.FailClosed,
            },
            // Both default to the permissive value and are reported until the
            // deployment resolves them, so a "no advisories" assertion has to
            // settle them first or it is really asserting the defaults.
            ClaimScopeMap = new ClaimScopeMapOptions
            {
                IncludeUnmappedClaimsInAccessTokens = false,
            },
        };
        var vault = new VaultOptions { Enabled = true, KeySource = "certificate" };
        var configuration = new ConfigurationBuilder()
            .AddInMemoryCollection(new Dictionary<string, string?>
            {
                ["Sufficit:Identity:TokenExchange:Enabled"] = "true",
            })
            .Build();

        Assert.Empty(ProductionPostureCheck.EvaluateAdvisories(
            [
                new StsProductionPostureContributor(root, configuration),
                new VaultProductionPostureContributor(vault),
            ],
            new SecurityPostureOptions(),
            Now));
    }

    [Fact]
    public void A_grant_outside_the_baseline_refuses_startup()
    {
        // The regression this exists for: ROPC was found enabled in a
        // configuration nobody meant to ship. Blocking, so the boot that
        // introduces it is the boot that reports it.
        foreach (var legacy in new[]
        {
            new LegacyGrantsOptions { Password = true },
            new LegacyGrantsOptions { None = true },
        })
        {
            var findings = Evaluate(new StsProductionPostureContributor(
                new SufficitIdentityOptions { LegacyGrants = legacy },
                new ConfigurationBuilder().Build()));

            var finding = Assert.Single(
                findings,
                f => f.Id == "legacy-grants-enabled");
            Assert.Equal(ProductionPostureSeverity.Blocking, finding.Severity);
        }

        Assert.DoesNotContain(
            Evaluate(new StsProductionPostureContributor(
                new SufficitIdentityOptions(),
                new ConfigurationBuilder().Build())),
            f => f.Id == "legacy-grants-enabled");
    }

    [Theory]
    // A wildcard, a bare scheme and an unsafe keyword each defeat the
    // directive they are in.
    [InlineData("script-src 'self' *; connect-src 'self'", true)]
    [InlineData("script-src 'self'; connect-src 'self' https:", true)]
    [InlineData("script-src 'self' 'unsafe-eval'; connect-src 'self'", true)]
    [InlineData("script-src 'self' *.cdn.example; connect-src 'self'", true)]
    // Other directives are not this finding's business, and a real origin is
    // a decision rather than a hole.
    [InlineData("script-src 'self'; connect-src 'self' https://api.example", false)]
    [InlineData("img-src *; script-src 'self'; connect-src 'self'", false)]
    public void A_permissive_csp_source_is_reported(string policy, bool reported)
    {
        var enforced = Evaluate(new StsProductionPostureContributor(
            new SufficitIdentityOptions
            {
                Csp = new CspOptions { Policy = policy, ReportOnly = false },
            },
            new ConfigurationBuilder().Build()));

        Assert.Equal(
            reported,
            enforced.Any(f => f.Id == "csp-policy-permissive-source"));

        if (!reported)
        {
            return;
        }

        // Report-only blocks nothing, so the same policy is a calibration
        // problem rather than a live hole.
        var advisories = ProductionPostureCheck.EvaluateAdvisories(
            [
                new StsProductionPostureContributor(
                    new SufficitIdentityOptions
                    {
                        Csp = new CspOptions { Policy = policy, ReportOnly = true },
                    },
                    new ConfigurationBuilder().Build()),
            ],
            new SecurityPostureOptions(),
            Now);
        Assert.Contains(advisories, f => f.Id == "csp-policy-permissive-source");
    }

    [Fact]
    public void One_certificate_for_two_purposes_is_reported_without_blocking()
    {
        var advisories = ProductionPostureCheck.EvaluateAdvisories(
            [
                new StsProductionPostureContributor(
                    new SufficitIdentityOptions
                    {
                        Certificates = new CertificatesOptions
                        {
                            SigningPath = "/etc/sufficit/identity/certificate.pfx",
                            // The same file reached by a different spelling.
                            EncryptionPath =
                                "/etc/sufficit/identity/../identity/certificate.pfx",
                        },
                    },
                    new ConfigurationBuilder().Build()),
            ],
            new SecurityPostureOptions(),
            Now);

        // Same file spelled two different ways is still one key.
        Assert.Contains(
            advisories,
            f => f.Id == "certificate-purpose-not-separated");

        // Advisory on purpose: production is in this state and cannot leave it
        // until a replacement certificate can be generated on the server.
        // Blocking would take the service down over a known, unresolvable one.
        Assert.DoesNotContain(
            Evaluate(new StsProductionPostureContributor(
                new SufficitIdentityOptions
                {
                    Certificates = new CertificatesOptions
                    {
                        SigningPath = "/etc/sufficit/identity/certificate.pfx",
                        EncryptionPath = "/etc/sufficit/identity/certificate.pfx",
                    },
                },
                new ConfigurationBuilder().Build())),
            f => f.Id == "certificate-purpose-not-separated");

        Assert.DoesNotContain(
            ProductionPostureCheck.EvaluateAdvisories(
                [
                    new StsProductionPostureContributor(
                        new SufficitIdentityOptions
                        {
                            Certificates = new CertificatesOptions
                            {
                                SigningPath = "/etc/sufficit/identity/signing.pfx",
                                EncryptionPath = "/etc/sufficit/identity/encryption.pfx",
                            },
                        },
                        new ConfigurationBuilder().Build()),
                ],
                new SecurityPostureOptions(),
                Now),
            f => f.Id == "certificate-purpose-not-separated");
    }

    [Fact]
    public void Permissive_defaults_are_reported_until_a_deployment_settles_them()
    {
        var advisories = ProductionPostureCheck.EvaluateAdvisories(
            [
                new StsProductionPostureContributor(
                    new SufficitIdentityOptions
                    {
                        Passkeys = new AccountPasskeyOptions
                        {
                            RequireUserVerification = false,
                        },
                    },
                    new ConfigurationBuilder().Build()),
            ],
            new SecurityPostureOptions(),
            Now);

        Assert.Contains(advisories, f => f.Id == "passkey-user-verification-optional");
        // Both default to the permissive value, which is the point: a default
        // nobody chose is still a decision the deployment is making.
        Assert.Contains(advisories, f => f.Id == "access-token-unmapped-claims");
        Assert.Contains(advisories, f => f.Id == "token-exchange-enabled-by-default");

        // Declaring the switch is what clears it, not turning it off: an
        // advisory that fires on every deployment teaches operators to skim.
        Assert.DoesNotContain(
            ProductionPostureCheck.EvaluateAdvisories(
                [
                    new StsProductionPostureContributor(
                        new SufficitIdentityOptions(),
                        new ConfigurationBuilder()
                            .AddInMemoryCollection(new Dictionary<string, string?>
                            {
                                ["Sufficit:Identity:TokenExchange:Enabled"] = "true",
                            })
                            .Build()),
                ],
                new SecurityPostureOptions(),
                Now),
            f => f.Id == "token-exchange-enabled-by-default");
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
