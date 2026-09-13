using Sufficit.Identity.Core.Networking;
using System.Net;
using System.Threading.RateLimiting;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Diagnostics.HealthChecks;
using Microsoft.AspNetCore.RateLimiting;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Sufficit.Identity.Application.Branding;
using Sufficit.Identity.Core.Branding;
using Sufficit.Identity.Core.Data;
using Sufficit.Identity.Management;
using Sufficit.Identity.Management.Authorization;
using Sufficit.Identity.Server;
using Sufficit.Identity.Scim;
using Sufficit.Identity.STS;
using Sufficit.Identity.STS.Mtls;
using Sufficit.Identity.UI.Abstractions.Hosting;
using Sufficit.Identity.UI;
using Sufficit.Identity.UI.Management;
using Sufficit.Identity.UI.Vault;
using Sufficit.Identity.Vault;

namespace Sufficit.Identity.Server;

/// <summary>
/// Startup checks that must pass before the host accepts traffic.
/// </summary>
internal static class HostStartupGuards
{
    /// <summary>
    /// Several security-critical stores depend on IDistributedCache; with more than
    /// one replica the in-memory fallback silently breaks them.
    /// </summary>
    public static void EnsureSharedDistributedCache(WebApplication app, SufficitIdentityOptions identityOptions)
    {
        // Several security-critical stores (DPoP replay cache + nonce store, CIBA
        // pending requests, front-channel logout context, passkey ceremony tickets)
        // depend on IDistributedCache. The default registration is
        // AddDistributedMemoryCache (single-node, in-process) — correct for one
        // replica, but in a multi-replica deployment each replica has its own isolated
        // cache, so DPoP replay detection, CIBA cross-replica polling and nonce
        // challenges silently break. When RequireShared is on and the registered
        // IDistributedCache is the in-memory fallback, fail fast (or warn) so the gap
        // is visible instead of a silent security degradation.
        if (identityOptions.DistributedCache.RequireShared && !app.Environment.IsDevelopment())
        {
            using var scope = app.Services.CreateScope();
            var cache = scope.ServiceProvider.GetService<Microsoft.Extensions.Caching.Distributed.IDistributedCache>();
            var isMemoryFallback = cache?.GetType().Name is "MemoryDistributedCache";
            if (isMemoryFallback)
            {
                var message =
                    "Sufficit:Identity:DistributedCache:RequireShared is true, but the registered " +
                    "IDistributedCache is the in-memory fallback (AddDistributedMemoryCache), which is NOT " +
                    "shared across replicas. DPoP replay protection, CIBA cross-replica polling, DPoP nonce " +
                    "challenges and front-channel logout context would silently break with >1 replica. " +
                    "Register a real shared cache (e.g. Redis via AddStackExchangeRedisCache) before scaling out, " +
                    "or set Sufficit:Identity:DistributedCache:RequireShared=false if this is genuinely a single-replica deployment.";

                throw new InvalidOperationException(message);
            }
        }
    }

    /// <summary>
    /// Loads the merged trusted proxy boundary and validates the deployment
    /// topology against it.
    /// </summary>
    public static async Task LoadTrustedProxiesAsync(WebApplication app, SufficitIdentityOptions identityOptions)
    {
        var proxySnapshots = app.Services.GetRequiredService<TrustedProxySnapshotStore>();
        await proxySnapshots.RefreshAsync();
        DeploymentTopologyPolicy.Validate(identityOptions, proxySnapshots.Current.EffectiveNetworks.Length,
            app.Environment.IsDevelopment());
        if (proxySnapshots.Current.EffectiveNetworks.Length == 0 && !app.Environment.IsDevelopment())
        {
            var message =
                "No trusted proxies are configured in appsettings or the database; only loopback proxies are trusted, so " +
                "X-Forwarded-* headers from remote reverse proxies will be ignored until it is set. " +
                "With the rate limiter partitioning by RemoteIpAddress, this means ALL token-endpoint " +
                "traffic shares ONE bucket (the proxy's IP) — a single source or even normal load can " +
                "trigger self-inflicted 429s for everyone.";

            // Item 5.1 [L4]: optionally make this a fatal startup error so a missing
            // TrustedProxies cannot silently turn the rate limiter into a self-DoS.
            if (identityOptions.RateLimit.FailOnUntrustedProxy)
            {
                throw new InvalidOperationException(message + " Set Sufficit:Identity:TrustedProxies " +
                    "(or disable Sufficit:Identity:RateLimit:FailOnUntrustedProxy to degrade to a warning).");
            }

            app.Logger.LogWarning(message);
        }
    }
}
