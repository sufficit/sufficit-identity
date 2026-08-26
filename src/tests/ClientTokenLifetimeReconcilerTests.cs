using System.Globalization;
using Microsoft.Extensions.DependencyInjection;
using OpenIddict.Abstractions;
using Sufficit.Identity.STS;
using Sufficit.Identity.Tests.Infrastructure;
using static OpenIddict.Abstractions.OpenIddictConstants;
using Xunit;

namespace Sufficit.Identity.Tests;

public sealed class ClientTokenLifetimeReconcilerTests
{
    [Fact]
    public async Task Reconciler_applies_seven_days_to_only_the_configured_client()
    {
        await using var factory = new ManagementTestFactory(
            extraConfiguration: new Dictionary<string, string?>
            {
                [$"Sufficit:Identity:Tokens:ClientOverrides:{TestDataSeeder.DeviceClientId}:AccessTokenLifetimeMinutes"] =
                    (7 * 24 * 60).ToString(CultureInfo.InvariantCulture),
            });
        await ((IAsyncLifetime)factory).InitializeAsync();
        await using var scope = factory.Services.CreateAsyncScope();
        var options = scope.ServiceProvider
            .GetRequiredService<SufficitIdentityOptions>();
        Assert.Equal(
            7 * 24 * 60,
            options.Tokens.ClientOverrides[TestDataSeeder.DeviceClientId]
                .AccessTokenLifetimeMinutes);

        var reconciler = scope.ServiceProvider
            .GetRequiredService<ClientTokenLifetimeReconciler>();
        Assert.Equal(1, await reconciler.ReconcileAsync());
        Assert.Equal(0, await reconciler.ReconcileAsync());

        var applications = scope.ServiceProvider
            .GetRequiredService<IOpenIddictApplicationManager>();
        var application = await applications.FindByClientIdAsync(
            TestDataSeeder.DeviceClientId);
        Assert.NotNull(application);
        var descriptor = new OpenIddictApplicationDescriptor();
        await applications.PopulateAsync(descriptor, application!);
        Assert.True(descriptor.Settings.TryGetValue(
            Settings.TokenLifetimes.AccessToken,
            out var raw));
        Assert.True(TimeSpan.TryParse(
            raw,
            CultureInfo.InvariantCulture,
            out var lifetime));
        Assert.Equal(TimeSpan.FromDays(7), lifetime);
    }
}
