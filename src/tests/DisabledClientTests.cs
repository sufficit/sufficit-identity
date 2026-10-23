using System.Net;
using System.Text.Json;
using Microsoft.Extensions.DependencyInjection;
using OpenIddict.Abstractions;
using Sufficit.Identity.Core.Services;
using Sufficit.Identity.Tests.Infrastructure;
using Xunit;

namespace Sufficit.Identity.Tests;

/// <summary>Plan E1: a disabled client is refused everywhere, and its tokens with it.</summary>
public sealed class DisabledClientTests
{
    [Fact]
    public async Task A_disabled_client_gets_no_token_and_its_tokens_stop_working_until_re_enabled()
    {
        using var factory = SufficitIdentityTestFactory.CreateIsolated(new Dictionary<string, string?>());
        await ((IAsyncLifetime)factory).InitializeAsync();
        var http = factory.CreateClient();

        var (status, body) = await TokenAsync(http);
        Assert.Equal(HttpStatusCode.OK, status);
        var accessToken = body.GetProperty("access_token").GetString()!;
        Assert.True(await IsActiveAsync(http, accessToken));

        await SetDisabledAsync(factory, disabled: true);

        (status, body) = await TokenAsync(http);
        Assert.Equal(HttpStatusCode.BadRequest, status);
        Assert.Equal(OpenIddictConstants.Errors.UnauthorizedClient, body.GetProperty("error").GetString());
        // A token issued before keeps nothing: introspection reports it inactive.
        Assert.False(await IsActiveAsync(http, accessToken));

        await SetDisabledAsync(factory, disabled: false);

        (status, _) = await TokenAsync(http);
        Assert.Equal(HttpStatusCode.OK, status);
        Assert.True(await IsActiveAsync(http, accessToken));
    }

    [Fact]
    public void The_state_round_trips_and_a_malformed_blob_reads_as_active()
    {
        var disablement = new ClientDisablement(DateTimeOffset.Parse("2026-10-22T21:00:00Z"), "operator", "leaked secret");
        var properties = new Dictionary<string, JsonElement>
        {
            [ClientOperationalState.PropertyName] = ClientOperationalState.Write(disablement),
        };

        Assert.Equal(disablement, ClientOperationalState.Read(properties));
        Assert.Equal(disablement, ClientOperationalState.Read(JsonSerializer.Serialize(properties)));
        Assert.Null(ClientOperationalState.Read("{\"sufficit:disabled\": \"yes\"}"));
        Assert.Null(ClientOperationalState.Read("not json sufficit:disabled"));
        Assert.Null(ClientOperationalState.Read((string?)null));
    }

    private static Task<(HttpStatusCode, JsonElement)> TokenAsync(HttpClient http) =>
        http.PostFormAsync("/connect/token", new Dictionary<string, string>
        {
            ["grant_type"] = "client_credentials",
            ["client_id"] = TestDataSeeder.ClientCredentialsClientId,
            ["client_secret"] = TestDataSeeder.ClientCredentialsClientSecret,
            ["scope"] = TestDataSeeder.ScopeName,
        });

    private static async Task<bool> IsActiveAsync(HttpClient http, string token)
    {
        using var request = new HttpRequestMessage(HttpMethod.Post, "/connect/introspect")
        {
            Content = new FormUrlEncodedContent(new Dictionary<string, string> { ["token"] = token }),
        };
        request.Headers.Authorization = IntrospectionTests.BasicAuthFor(
            TestDataSeeder.IntrospectionClientId, TestDataSeeder.IntrospectionClientSecret);
        using var response = await http.SendAsync(request);
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        using var document = JsonDocument.Parse(await response.Content.ReadAsStringAsync());
        return document.RootElement.GetProperty("active").GetBoolean();
    }

    private static async Task SetDisabledAsync(SufficitIdentityTestFactory factory, bool disabled)
    {
        using var scope = factory.Services.CreateScope();
        var applications = scope.ServiceProvider.GetRequiredService<IOpenIddictApplicationManager>();
        var application = await applications.FindByClientIdAsync(TestDataSeeder.ClientCredentialsClientId);
        var descriptor = new OpenIddictApplicationDescriptor();
        await applications.PopulateAsync(descriptor, application!);
        if (disabled)
            descriptor.Properties[ClientOperationalState.PropertyName] = ClientOperationalState.Write(
                new ClientDisablement(DateTimeOffset.UtcNow, "test", "test"));
        else
            descriptor.Properties.Remove(ClientOperationalState.PropertyName);
        await applications.UpdateAsync(application!, descriptor);
        await scope.ServiceProvider.GetRequiredService<IDisabledClientRegistry>().PublishChangeAsync();
    }
}
