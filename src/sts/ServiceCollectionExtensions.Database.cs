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

/// <summary>
/// DI extensions that wire up the Sufficit Identity STS server
/// (ASP.NET Core Identity + OpenIddict server/validation).
/// </summary>
public static partial class ServiceCollectionExtensions
{
    internal static string ApplyDatabaseConnectionPolicy(
        string connectionString,
        DatabaseConnectionPoolOptions options,
        bool tolerateInvalidDevelopmentValue = false)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(connectionString);
        ArgumentNullException.ThrowIfNull(options);

        try
        {
            var builder = new MySqlConnectionStringBuilder(connectionString);
            var maximumSize = Math.Clamp(options.MaximumSize, 1, 10_000);
            var minimumSize = Math.Clamp(options.MinimumSize, 0, maximumSize);

            builder.Pooling = true;
            builder.MaximumPoolSize = (uint)maximumSize;
            builder.MinimumPoolSize = (uint)minimumSize;
            builder.ConnectionTimeout = (uint)Math.Clamp(
                options.ConnectionTimeoutSeconds,
                1,
                300);
            builder.DefaultCommandTimeout = (uint)Math.Clamp(
                options.CommandTimeoutSeconds,
                1,
                3_600);
            builder.ConnectionLifeTime = (uint)Math.Clamp(
                options.ConnectionLifetimeSeconds,
                0,
                86_400);
            builder.ConnectionIdleTimeout = (uint)Math.Clamp(
                options.ConnectionIdleTimeoutSeconds,
                0,
                3_600);
            builder.ConnectionReset = options.ResetOnCheckout;
            builder.ApplicationName = string.IsNullOrWhiteSpace(options.ApplicationName)
                ? "Sufficit.Identity"
                : options.ApplicationName.Trim()[..Math.Min(
                    options.ApplicationName.Trim().Length,
                    64)];

            return builder.ConnectionString;
        }
        catch (ArgumentException) when (tolerateInvalidDevelopmentValue)
        {
            // Test hosts replace the provider registration after composing the
            // STS and historically use the sentinel value "unused". Preserve
            // that development-only seam; production still fails fast.
            return connectionString;
        }
    }

    private static string? ResolveSecret(
        ISecretStore secretStore,
        string logicalName)
    {
        return secretStore.GetSecretAsync(logicalName)
            .GetAwaiter()
            .GetResult();
    }
}
