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
    private static void ValidateAdvancedProtocolOptions(SufficitIdentityOptions options)
    {
        ValidateTokenFormatMap(
            options.Tokens.AccessTokenFormatsByClient,
            "Tokens:AccessTokenFormatsByClient");
        ValidateTokenFormatMap(
            options.Tokens.AccessTokenFormatsByResource,
            "Tokens:AccessTokenFormatsByResource");

        // Nonce-based CSP works by rewriting the style-src directive. A policy
        // that does not declare one (for example a deployment that folded
        // styles into default-src) accepts Csp:UseNonce=true, publishes a nonce
        // and renders nonce attributes while changing nothing — the fallback
        // directive still carries 'unsafe-inline'. Silently doing nothing is
        // the worst outcome for a security switch: it reads as enabled.
        if (options.Csp.Enabled
            && options.Csp.UseNonce
            && !HasDirective(options.Csp.Policy, "style-src"))
        {
            throw new InvalidOperationException(
                "Sufficit:Identity:Csp:UseNonce=true requires the policy to declare "
                + "a 'style-src' directive: the nonce is applied by rewriting it. "
                + "Add style-src to Sufficit:Identity:Csp:Policy, or disable "
                + "UseNonce so the setting does not claim protection it is not "
                + "providing.");
        }

        Features.ProtocolFeatureCatalog.Validate(options);
    }

    private static void ValidateTokenFormatMap(
        IReadOnlyDictionary<string, AccessTokenStorageMode> values,
        string setting)
    {
        if (values.Count > 4096
            || values.Keys.Any(key =>
                string.IsNullOrWhiteSpace(key)
                || key.Length > 512
                || !string.Equals(key, key.Trim(), StringComparison.Ordinal)))
        {
            throw new InvalidOperationException(
                $"Sufficit:Identity:{setting} contains an invalid or excessive exact-match token-format mapping.");
        }
    }

    /// <summary>
    /// Whether a CSP policy string declares the given directive.
    /// </summary>
    private static bool HasDirective(string? policy, string directive) =>
        (policy ?? string.Empty)
            .Split(';', StringSplitOptions.RemoveEmptyEntries
                | StringSplitOptions.TrimEntries)
            .Any(value =>
                value.Equals(directive, StringComparison.OrdinalIgnoreCase)
                || value.StartsWith(
                    directive + " ",
                    StringComparison.OrdinalIgnoreCase));
}
