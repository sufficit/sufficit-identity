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

internal static class UiCompositionValidation
{
    public static void Validate(
        WebApplication app,
        IdentityUiHostingOptions uiHostingOptions,
        bool mgmtEnabled,
        bool vaultUiEnabled)
    {
        // Catches: duplicate modules, incompatible versions, surface requested
        // without a module, management UI without management API. All fail-fast
        // with a clear message instead of silent no-ops or runtime 404s.
        {
            var hostVersion = typeof(Program).Assembly.GetName().Version ?? new Version(0, 4, 0);
            var registry = app.Services.GetService<UiModuleRegistry>();
            if (registry is not null)
            {
                // Collect all UiModuleDescriptor singletons registered by the UI modules.
                foreach (var descriptor in app.Services.GetServices<UiModuleDescriptor>())
                {
                    registry.Register(descriptor);
                }

                // Validate: incompatible versions.
                foreach (var module in registry.Modules)
                {
                    if (module.MinHostVersion > hostVersion)
                    {
                        throw new UiCompositionException(
                            $"UI module '{module.Id}' v{module.Version} requires host >= " +
                            $"v{module.MinHostVersion}, but the host is v{hostVersion}.");
                    }
                }

                // Validate: surface requested but no module registered for it.
                if (uiHostingOptions.Public.IsEmbedded && !registry.HasSurface(UiSurface.Public))
                {
                    throw new UiCompositionException(
                        "Public UI surface is Embedded but no public UI module was registered.");
                }

                if (uiHostingOptions.Management.IsEmbedded && !registry.HasSurface(UiSurface.Management))
                {
                    if (!mgmtEnabled)
                    {
                        throw new UiCompositionException(
                            "Management UI surface is Embedded but the management API " +
                            "(Sufficit:Identity:Management:Enabled) is disabled.");
                    }
                    throw new UiCompositionException(
                        "Management UI surface is Embedded but no management UI module was registered.");
                }

                if (vaultUiEnabled && !registry.HasSurface(UiSurface.Vault))
                {
                    throw new UiCompositionException(
                        "Vault UI surface is Embedded but no Vault UI module was registered.");
                }
            }
        }
    }
}
