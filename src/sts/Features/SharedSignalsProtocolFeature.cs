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
/// OpenID Shared Signals Framework with CAEP events: push delivery, optional
/// stream management REST surface (RFC 8933) and the security event trigger
/// used by account, management and SCIM.
/// </summary>
internal sealed class SharedSignalsProtocolFeature : IProtocolFeature
{
    public string Name => "shared-signals";

    public bool IsEnabled(SufficitIdentityOptions options) => options.SharedSignals.Enabled;

    public void Validate(SufficitIdentityOptions options)
    {
        var signals = options.SharedSignals;
        if (!signals.Enabled)
        {
            return;
        }

        if (!Uri.TryCreate(options.Issuer, UriKind.Absolute, out var issuer) ||
            issuer.Scheme != Uri.UriSchemeHttps)
            throw new InvalidOperationException(
                "SSF/CAEP requires an explicit HTTPS Sufficit:Identity:Issuer.");
        if (issuer.AbsolutePath != "/")
            throw new InvalidOperationException(
                "This SSF/CAEP transmitter currently requires an issuer without a path component.");

        var duplicate = signals.Receivers
            .Where(receiver => !string.IsNullOrWhiteSpace(receiver.Id))
            .GroupBy(receiver => receiver.Id, StringComparer.Ordinal)
            .FirstOrDefault(group => group.Count() > 1);
        if (duplicate is not null)
            throw new InvalidOperationException(
                $"SSF/CAEP receiver id '{duplicate.Key}' is duplicated.");

        foreach (var receiver in signals.Receivers)
        {
            if (string.IsNullOrWhiteSpace(receiver.Id) ||
                string.IsNullOrWhiteSpace(receiver.Audience) ||
                !Uri.TryCreate(receiver.Endpoint, UriKind.Absolute, out var endpoint) ||
                endpoint.Scheme != Uri.UriSchemeHttps ||
                endpoint.Fragment.Length != 0)
                throw new InvalidOperationException(
                    "Each SSF/CAEP receiver requires an id, audience and fragment-free HTTPS endpoint.");
        }
    }

    public void ConfigureServices(IServiceCollection services, ProtocolFeatureContext context)
    {
        var options = context.Options;
        if (options.SharedSignals.Enabled)
        {
            services.AddSingleton(new SharedSignals.CaepEventGenerator(
                context.AuxiliarySigningCredentials, options.Issuer!));
            services.AddHttpClient<SharedSignals.ISharedSignalsDispatcher,
                    SharedSignals.SharedSignalsPushDispatcher>()
                .ConfigureHttpClient(client =>
                    client.Timeout = TimeSpan.FromSeconds(7))
                .UseSafeOutboundHttp(options.OutboundHttp);

            // Translates credential and device changes from the account,
            // management and SCIM surfaces into SSF dispatcher calls.
            services.AddScoped<ISecurityEventTrigger,
                SharedSignals.SharedSignalsSecurityEventTrigger>();

            // The stream store is available whenever SSF is on, so the push
            // dispatcher can route poll streams to the persistent queue even
            // when the REST API is not exposed.
            services.AddScoped<SharedSignals.ISsfStreamStore, SharedSignals.SsfStreamStore>();
            services.AddSingleton<SharedSignals.ISsfSubscriptionMatcher,
                SharedSignals.SsfSubscriptionMatcher>();
        }
        else
        {
            services.AddSingleton<SharedSignals.ISharedSignalsDispatcher,
                SharedSignals.NullSharedSignalsDispatcher>();
            // Always resolvable: account, management and SCIM services take this
            // as a hard dependency regardless of the SSF feature flag.
            services.AddSingleton<ISecurityEventTrigger,
                SharedSignals.NullSecurityEventTrigger>();
        }

        // Stream-management REST surface (RFC 8933, opt-in): the controllers'
        // authorization policy exists only when the operator opts in.
        if (options.SharedSignals is { Enabled: true, StreamManagementEnabled: true })
        {
            services.AddHttpClient("ssf-verification")
                .ConfigureHttpClient(client => client.Timeout = TimeSpan.FromSeconds(7))
                .UseSafeOutboundHttp(options.OutboundHttp);
            services.AddScoped<IAuthorizationHandler, Controllers.SsfScopeHandler>();
            services.AddScoped<IAuthorizationHandler, Controllers.SsfMfaHandler>();
            services.AddAuthorizationBuilder()
                .AddPolicy("sufficit-ssf-transmitter", policy =>
                {
                    policy.AuthenticationSchemes.Add(
                        OpenIddictValidationAspNetCoreDefaults.AuthenticationScheme);
                    policy.RequireAuthenticatedUser();
                    policy.Requirements.Add(
                        new Controllers.SsfScopeRequirement(options.SharedSignals.RequiredScope));
                    if (options.SharedSignals.RequireMfa)
                    {
                        policy.Requirements.Add(new Controllers.SsfMfaRequirement());
                    }
                });
        }
    }
}
