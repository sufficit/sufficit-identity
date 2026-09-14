using System.Text.Json.Nodes;
using Microsoft.AspNetCore.Authorization;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using OpenIddict.Server;
using OpenIddict.Validation.AspNetCore;
using Sufficit.Identity.Application.Security;
using Sufficit.Identity.Core.Data;
using Sufficit.Identity.Management;

namespace Sufficit.Identity.STS.Features;

/// <summary>
/// JWT Secured Authorization Response Mode (JARM): signed, optionally
/// encrypted authorization responses.
/// </summary>
internal sealed class JarmProtocolFeature : IProtocolFeature
{
    public string Name => "jarm";

    public bool IsEnabled(SufficitIdentityOptions options) => options.Jarm.Enabled;

    public IEnumerable<string> RuntimeCapabilities(SufficitIdentityOptions options) =>
        options.Jarm.Enabled ? [ManagementRuntimeCapabilities.Jarm] : [];

    public void Validate(SufficitIdentityOptions options)
    {
        if (!options.Jarm.Enabled)
        {
            return;
        }

        if (options.Jarm.LifetimeSeconds is < 1 or > 600)
            throw new InvalidOperationException(
                "JARM response lifetime must be between 1 and 600 seconds.");
        if (!Uri.TryCreate(options.Issuer, UriKind.Absolute, out _))
            throw new InvalidOperationException(
                "JARM requires an explicit absolute Sufficit:Identity:Issuer.");
    }

    public void ConfigureServices(IServiceCollection services, ProtocolFeatureContext context)
    {
        var options = context.Options;
        if (!options.Jarm.Enabled)
        {
            return;
        }

        var issuer = string.IsNullOrWhiteSpace(options.Issuer)
            ? "https://localhost/"
            : options.Issuer;
        services.AddSingleton(new Jarm.JarmResponseGenerator(
            context.AuxiliarySigningCredentials,
            issuer,
            TimeSpan.FromSeconds(options.Jarm.LifetimeSeconds)));
        services.AddScoped<Jarm.IJarmClientEncryptionCredentialsResolver,
            Jarm.JarmClientEncryptionCredentialsResolver>();
    }

    public void ConfigureServer(OpenIddictServerBuilder server, ProtocolFeatureContext context)
    {
        if (!context.Options.Jarm.Enabled)
        {
            return;
        }

        server.Configure(serverOptions =>
        {
            serverOptions.ResponseModes.Add(Jarm.JarmAuthorizationResponseHandler.QueryJwt);
            serverOptions.ResponseModes.Add(Jarm.JarmAuthorizationResponseHandler.FragmentJwt);
            serverOptions.ResponseModes.Add(Jarm.JarmAuthorizationResponseHandler.FormPostJwt);
            serverOptions.ResponseModes.Add(Jarm.JarmAuthorizationResponseHandler.Jwt);
        });
        server.AddEventHandler(Jarm.JarmAuthorizationResponseHandler.Descriptor);
    }

    public void ConfigureDiscovery(
        OpenIddictServerEvents.HandleConfigurationRequestContext discovery,
        ProtocolFeatureContext context)
    {
        var jarm = context.Options.Jarm;
        if (!jarm.Enabled)
        {
            return;
        }

        // JARM final section 4 defines this metadata value.
        discovery.Metadata["authorization_signing_alg_values_supported"] =
            System.Text.Json.JsonSerializer.SerializeToNode(
                new[] { context.AuxiliarySigningCredentials.Algorithm });

        // With JWE encryption configured, advertise the key-management and
        // content-encryption algorithms (FAPI 2.0 signed+encrypted mode).
        if (jarm.Encryption.Enabled)
        {
            discovery.Metadata["authorization_encryption_alg_values_supported"] =
                System.Text.Json.JsonSerializer.SerializeToNode(
                    new[] { jarm.Encryption.KeyManagementAlgorithm });
            discovery.Metadata["authorization_encryption_enc_values_supported"] =
                System.Text.Json.JsonSerializer.SerializeToNode(
                    new[] { jarm.Encryption.ContentEncryptionAlgorithm });
        }
    }
}
