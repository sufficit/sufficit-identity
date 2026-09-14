using System.Security.Cryptography.X509Certificates;
using System.Security.Claims;
using System.Text.Json.Nodes;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authentication.OAuth;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Identity.UI.Services;
using Microsoft.AspNetCore.WebUtilities;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.Extensions.Logging;
using MySqlConnector;
using OpenIddict.Abstractions;
using OpenIddict.Server;
using OpenIddict.Validation.AspNetCore;
using Sufficit.Identity.Application.Branding;
using Sufficit.Identity.Core;
using Sufficit.Identity.Core.Branding;
using Sufficit.Identity.Core.Data;
using Sufficit.Identity.Core.Entities;
using Sufficit.Identity.Core.Services;
using Sufficit.Identity.Application.Accounts;
using Sufficit.Identity.Application.Security;
using Sufficit.Identity.Application.Diagnostics;
using Sufficit.Identity.STS.Diagnostics;
using Sufficit.Identity.STS.Email;
using Sufficit.Identity.STS.Metrics;
using Sufficit.Identity.Core.Metrics;
using Sufficit.Identity.Management;
using Sufficit.Identity.STS.Integrations;
using Sufficit.Identity.Vault;
using static OpenIddict.Abstractions.OpenIddictConstants;

namespace Sufficit.Identity.STS;

public static partial class ServiceCollectionExtensions
{
    /// <summary>
    /// Registers the protocol features layered on the OpenIddict pipeline:
    /// back-channel and front-channel logout, durable protocol state and DPoP,
    /// JAR bounds, JARM, Shared Signals with stream management, and CIBA.
    /// Registration order within this method is significant and unchanged
    /// from the original composition root.
    /// </summary>
    private static void AddProtocolFeatures(
        IServiceCollection services,
        SufficitIdentityOptions options,
        Microsoft.IdentityModel.Tokens.SigningCredentials auxiliarySigningCredentials)
    {
        // ---- OIDC Back-Channel Logout 1.0 (item 3.2 [L1]) ----
        // OpenIddict 7.6 only consumes logout_tokens; the STS generates them
        // (LogoutTokenGenerator) and distributes them (BackchannelLogoutDistributor).
        // The IBackchannelLogoutDispatcher is ALWAYS registered (so the
        // AuthorizationController can take it as a hard dependency): when the
        // feature is disabled, a no-op implementation is used, so logout just
        // skips RP fan-out. The real generator+distributor+HttpClient are only
        // wired when Enabled, to avoid creating an HttpClient that is never used.
        if (options.BackchannelLogout.Enabled)
        {
            var issuer = string.IsNullOrWhiteSpace(options.Issuer)
                ? "https://localhost/"
                : options.Issuer;

            services.AddSingleton(new Logout.LogoutTokenGenerator(
                auxiliarySigningCredentials, issuer));
            services.AddHttpClient<Logout.IBackchannelLogoutDispatcher, Logout.BackchannelLogoutDistributor>()
                .ConfigureHttpClient(client => client.Timeout = TimeSpan.FromSeconds(7))
                .UseSafeOutboundHttp(options.OutboundHttp);
        }
        else
        {
            services.AddSingleton<Logout.IBackchannelLogoutDispatcher, Logout.NullBackchannelLogoutDispatcher>();
        }

        // ---- OIDC Front-Channel Logout 1.0 ----
        // RP URI lists are resolved from canonical application metadata before
        // local sign-out and kept behind an opaque, one-time, two-minute cache
        // key while OpenIddict completes the end-session response.
        if (options.FrontchannelLogout.Enabled)
        {
            services.AddScoped<Logout.IFrontchannelLogoutDispatcher,
                Logout.FrontchannelLogoutDispatcher>();
        }
        else
        {
            services.AddSingleton<Logout.IFrontchannelLogoutDispatcher,
                Logout.NullFrontchannelLogoutDispatcher>();
        }

        // ---- DPoP (RFC 9449, item 3.1) ----
        // The proof validator is registered unconditionally (cheap; it only
        // runs when invoked from AuthorizationController.Exchange AND the
        // option is enabled). The distributed replay cache and nonce store use
        // IDistributedCache (registered above as AddDistributedMemoryCache;
        // swap for Redis when multi-replica).
        // Durable key/value state for protocol features that have no table of
        // their own (DPoP nonces, front-channel logout context, passkey
        // ceremonies). See ProtocolStateStore — eval 2026-08-30, F-4.
        services.TryAddSingleton<IProtocolStateStore>(sp =>
            new DatabaseProtocolStateStore(
                sp.GetRequiredService<IDbContextFactory<AppDbContext>>(),
                TimeProvider.System));

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

        // Distributed, partition-bound DPoP nonce (RFC 9449 §8). The cache
        // payload is encrypted through IKeyVault when enabled, so a shared
        // Redis/SQL cache does not expose nonce material at rest.
        // Durable primary with the cache accepted during a rolling deployment
        // (eval 2026-08-30, F-4): a nonce challenge issued by one replica has to
        // be honored by whichever replica receives the client's retry.
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

        if (options.Jar.Enabled)
        {
            if (options.Jar.MaxLifetimeSeconds is < 1 or > 600
                || options.Jar.RemoteJwksMaxBytes is < 1024 or > 1_048_576
                || options.Jar.RemoteJwksTimeoutSeconds is < 1 or > 30
                || options.Jar.RemoteJwksCacheSeconds is < 1 or > 86_400
                || options.Jar.RemoteJwksStaleSeconds is < 0 or > 86_400
                || options.Jar.RemoteJwksMaxCacheEntries is < 1 or > 4096)
            {
                throw new InvalidOperationException(
                    "JAR lifetime and remote JWKS timeout/size/cache settings are outside their supported security bounds.");
            }
        }

        // Optional protocol features (CIBA, ID-JAG, JARM, Shared Signals) own
        // their registrations; see Features/ProtocolFeatureCatalog.
        Features.ProtocolFeatureCatalog.ConfigureServices(
            services,
            new Features.ProtocolFeatureContext(options, auxiliarySigningCredentials));
    }
}
