using System.Text.Json.Nodes;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using OpenIddict.Server;
using Sufficit.Identity.Core.Data;
using Sufficit.Identity.Management;

namespace Sufficit.Identity.STS.Features;

/// <summary>
/// OAuth 2.0 Demonstrating Proof of Possession (RFC 9449): proof validation,
/// nonce challenges, sender-constrained tokens and proofs at the API.
/// </summary>
internal sealed class DpopProtocolFeature : IProtocolFeature
{
    public string Name => "dpop";

    public bool IsEnabled(SufficitIdentityOptions options) => options.Dpop.Enabled;

    public IEnumerable<string> RuntimeCapabilities(SufficitIdentityOptions options) =>
        options.Dpop.Enabled ? [ManagementRuntimeCapabilities.Dpop] : [];

    public void ConfigureServices(IServiceCollection services, ProtocolFeatureContext context)
    {
        // Registered regardless of the option: the proof validator only runs
        // when the token dispatcher finds DPoP enabled, and the replay cache is
        // also the single-use store for request objects and client assertions.
        services.AddSingleton<Dpop.DistributedDpopReplayCache>();
        services.AddSingleton(sp => new Dpop.DatabaseDpopReplayCache(
            sp.GetRequiredService<IDbContextFactory<AppDbContext>>(),
            TimeProvider.System));
        services.AddSingleton<Dpop.IAtomicDpopReplayCache>(sp =>
            sp.GetRequiredService<Dpop.DatabaseDpopReplayCache>());
        services.AddSingleton<Dpop.IDpopReplayCache, Dpop.RollingDpopReplayCache>();
        services.AddSingleton(sp => new Dpop.DpopProofValidator(
            TimeProvider.System,
            Microsoft.Extensions.Logging.LoggerFactoryExtensions.CreateLogger<Dpop.DpopProofValidator>(
                sp.GetRequiredService<Microsoft.Extensions.Logging.ILoggerFactory>()),
            sp.GetService<Dpop.IDpopReplayCache>()));

        // Partition-bound nonce (§8) with a durable primary, so a challenge
        // issued by one replica is honored by whichever replica receives the
        // retry. Payloads are encrypted through IKeyVault when it is enabled.
        services.AddSingleton<Dpop.IDpopNonceStore>(sp =>
            sp.GetRequiredService<Dpop.RollingDpopNonceStore>());
        services.AddSingleton(sp => new Dpop.DatabaseDpopNonceStore(
            sp.GetRequiredService<IProtocolStateStore>(),
            ttl: null,
            timeProvider: TimeProvider.System,
            keyVault: sp.GetRequiredService<Sufficit.Identity.Vault.IKeyVault>()));
        services.AddSingleton(sp => new Dpop.RollingDpopNonceStore(
            sp.GetRequiredService<Dpop.DatabaseDpopNonceStore>(),
            sp.GetRequiredService<Dpop.DistributedDpopNonceStore>()));
        // Concrete registration is separate so tests and deployment-specific
        // composition roots can resolve the implementation directly.
        services.AddSingleton(sp => new Dpop.DistributedDpopNonceStore(
            sp.GetRequiredService<Microsoft.Extensions.Caching.Distributed.IDistributedCache>(),
            timeProvider: TimeProvider.System,
            keyVault: sp.GetRequiredService<Sufficit.Identity.Vault.IKeyVault>()));
    }

    public void ConfigureServer(OpenIddictServerBuilder server, ProtocolFeatureContext context)
    {
        if (!context.Options.Dpop.Enabled)
        {
            return;
        }

        server.AddEventHandler(Dpop.AttachDpopConfirmation.Descriptor);
        server.AddEventHandler(Dpop.AttachDpopTokenType.Descriptor);
        server.AddEventHandler(Dpop.ExtractDpopUserInfoToken.Descriptor);
        server.AddEventHandler(Dpop.ValidateDpopAccessTokenProof.Descriptor);
        // RFC 9449 10.1: a proof sent with a pushed authorization request
        // binds the code, with or without a dpop_jkt parameter.
        server.AddEventHandler(
            Dpop.BindPushedAuthorizationToDpopProof.Descriptor);
    }

    public void ConfigureValidation(OpenIddictValidationBuilder validation, ProtocolFeatureContext context)
    {
        if (!context.Options.Dpop.Enabled)
        {
            return;
        }

        validation.AddEventHandler(Dpop.ExtractDpopValidationToken.Descriptor);
        validation.AddEventHandler(Dpop.ValidateDpopApiAccessTokenProof.Descriptor);
    }

    public void ConfigureDiscovery(
        OpenIddictServerEvents.HandleConfigurationRequestContext discovery,
        ProtocolFeatureContext context)
    {
        // The algorithms DpopProofValidator accepts (EC P-256 and RSA).
        if (context.Options.Dpop.Enabled)
        {
            discovery.Metadata["dpop_signing_alg_values_supported"] =
                System.Text.Json.JsonSerializer.SerializeToNode(new[] { "ES256", "RS256" });
        }
    }
}
