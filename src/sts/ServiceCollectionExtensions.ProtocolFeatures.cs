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
    /// Registers the durable protocol state shared by features, then every
    /// optional protocol feature through <see cref="Features.ProtocolFeatureCatalog"/>.
    /// </summary>
    private static void AddProtocolFeatures(
        IServiceCollection services,
        SufficitIdentityOptions options,
        Microsoft.IdentityModel.Tokens.SigningCredentials auxiliarySigningCredentials)
    {
        // Durable key/value state for protocol features that have no table of
        // their own (DPoP nonces, front-channel logout context, passkey
        // ceremonies). See ProtocolStateStore — eval 2026-08-30, F-4.
        services.TryAddSingleton<IProtocolStateStore>(sp =>
            new DatabaseProtocolStateStore(
                sp.GetRequiredService<IDbContextFactory<AppDbContext>>(),
                TimeProvider.System));

        // Optional protocol features own their registrations; see
        // Features/ProtocolFeatureCatalog.
        Features.ProtocolFeatureCatalog.ConfigureServices(
            services,
            new Features.ProtocolFeatureContext(options, auxiliarySigningCredentials));
    }
}
