using System.Net;
using System.Net.Http.Json;
using System.Security.Claims;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using OpenIddict.Abstractions;
using Sufficit.Identity.Core.Data;
using Sufficit.Identity.Management.Clients;
using Sufficit.Identity.Management.Controllers;
using Sufficit.Identity.Management.Authorization;
using Sufficit.Identity.Tests.Infrastructure;
using Xunit;

namespace Sufficit.Identity.Tests;

public sealed class ClientDraftsControllerTests
{
    [Fact]
    public async Task Draft_is_protected_and_confidential_client_secret_is_returned_once()
    {
        using var factory = new ManagementTestFactory();
        await ((IAsyncLifetime)factory).InitializeAsync();
        var client = factory.CreateClient();

        var draft = await CreateDraftAsync(client, ManagementClientProfiles.Service);
        draft.Values.ClientId = $"draft-service-{Guid.NewGuid():N}";
        draft.Values.DisplayName = "Serviço criado pelo configurador";
        var saved = await SaveDraftAsync(client, draft);

        await using (var scope = factory.Services.CreateAsyncScope())
        {
            var database = scope.ServiceProvider.GetRequiredService<AppDbContext>();
            var row = await database.ManagementClientDrafts
                .AsNoTracking()
                .SingleAsync(item => item.Id == saved.Id);

            Assert.DoesNotContain(saved.Values.ClientId, row.ProtectedPayload, StringComparison.Ordinal);
            Assert.DoesNotContain(saved.Values.DisplayName, row.ProtectedPayload, StringComparison.Ordinal);
            Assert.NotEqual("{}", row.ProtectedPayload);
        }

        using var completedResponse = await client.PostAsJsonAsync(
            $"/api/client-drafts/{saved.Id:D}/complete",
            new CompleteClientDraftRequest { Version = saved.Version });
        Assert.Equal(HttpStatusCode.OK, completedResponse.StatusCode);
        var completed = await completedResponse.Content
            .ReadFromJsonAsync<CompleteManagementClientDraftResult>();
        Assert.NotNull(completed);
        Assert.False(string.IsNullOrWhiteSpace(completed.OneTimeSecret));
        Assert.Equal(saved.Values.ClientId, completed.Client.ClientId);
        Assert.Equal("confidential", completed.Client.Type);

        using var repeatedResponse = await client.PostAsJsonAsync(
            $"/api/client-drafts/{saved.Id:D}/complete",
            new CompleteClientDraftRequest { Version = saved.Version });
        Assert.Equal(HttpStatusCode.OK, repeatedResponse.StatusCode);
        var repeated = await repeatedResponse.Content
            .ReadFromJsonAsync<CompleteManagementClientDraftResult>();
        Assert.NotNull(repeated);
        Assert.Null(repeated.OneTimeSecret);
    }

    [Fact]
    public async Task Device_profile_persists_device_and_token_endpoint_permissions()
    {
        using var factory = new ManagementTestFactory();
        await ((IAsyncLifetime)factory).InitializeAsync();
        var client = factory.CreateClient();

        var draft = await CreateDraftAsync(client, ManagementClientProfiles.Device);
        draft.Values.ClientId = $"draft-device-{Guid.NewGuid():N}";
        draft.Values.DisplayName = "CLI Device Flow";
        var saved = await SaveDraftAsync(client, draft);

        using var response = await client.PostAsJsonAsync(
            $"/api/client-drafts/{saved.Id:D}/complete",
            new CompleteClientDraftRequest { Version = saved.Version });
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        var completed = await response.Content
            .ReadFromJsonAsync<CompleteManagementClientDraftResult>();
        Assert.NotNull(completed);

        Assert.Contains(
            OpenIddictConstants.Permissions.GrantTypes.DeviceCode,
            completed.Client.Permissions);
        Assert.Contains(
            OpenIddictConstants.Permissions.Endpoints.DeviceAuthorization,
            completed.Client.Permissions);
        Assert.Contains(
            OpenIddictConstants.Permissions.Endpoints.Token,
            completed.Client.Permissions);
        Assert.Null(completed.OneTimeSecret);
    }

    [Fact]
    public async Task Saving_with_stale_version_returns_conflict_without_overwriting_draft()
    {
        using var factory = new ManagementTestFactory();
        await ((IAsyncLifetime)factory).InitializeAsync();
        var client = factory.CreateClient();

        var draft = await CreateDraftAsync(client, ManagementClientProfiles.Spa);
        var staleVersion = draft.Version;
        draft.Values.ClientId = $"draft-spa-{Guid.NewGuid():N}";
        draft.Values.DisplayName = "SPA original";
        var saved = await SaveDraftAsync(client, draft);

        draft.Values.DisplayName = "Sobrescrita indevida";
        using var staleResponse = await client.PutAsJsonAsync(
            $"/api/client-drafts/{draft.Id:D}",
            new SaveClientDraftRequest
            {
                Version = staleVersion,
                CurrentStep = ManagementClientDraftSteps.Identity,
                Values = draft.Values,
            });

        Assert.Equal(HttpStatusCode.Conflict, staleResponse.StatusCode);
        var current = await client.GetFromJsonAsync<ManagementClientDraftDetail>(
            $"/api/client-drafts/{saved.Id:D}");
        Assert.NotNull(current);
        Assert.Equal("SPA original", current.Values.DisplayName);
    }

    [Fact]
    public async Task Frontchannel_logout_must_share_origin_with_a_redirect_uri()
    {
        using var factory = new ManagementTestFactory();
        await ((IAsyncLifetime)factory).InitializeAsync();
        var client = factory.CreateClient();

        var draft = await CreateDraftAsync(client, ManagementClientProfiles.Web);
        draft.Values.ClientId = $"draft-web-{Guid.NewGuid():N}";
        draft.Values.DisplayName = "Portal web";
        draft.Values.RedirectUris = ["https://portal.example.test/callback"];
        draft.Values.FrontchannelLogoutUri = "https://other.example.test/logout";
        var saved = await SaveDraftAsync(client, draft);

        Assert.Contains(
            saved.Validation.Errors,
            issue => issue.Code == "frontchannel_logout_origin_mismatch"
                && issue.Step == ManagementClientDraftSteps.Uris);
    }

    [Fact]
    public async Task Draft_is_bound_to_the_operator_that_created_it()
    {
        using var factory = new ManagementTestFactory();
        await ((IAsyncLifetime)factory).InitializeAsync();

        await using var scope = factory.Services.CreateAsyncScope();
        var service = scope.ServiceProvider
            .GetRequiredService<IClientConfigurationDraftService>();
        var alice = ContextFor("operator-alice");
        var bob = ContextFor("operator-bob");
        var draft = await service.CreateAsync(ManagementClientProfiles.Spa, alice);

        await Assert.ThrowsAsync<ManagementNotFoundException>(
            () => service.GetAsync(draft.Id, bob));
        Assert.NotNull(await service.GetAsync(draft.Id, alice));
    }

    private static async Task<ManagementClientDraftDetail> CreateDraftAsync(
        HttpClient client,
        string profile)
    {
        using var response = await client.PostAsJsonAsync(
            "/api/client-drafts",
            new CreateClientDraftRequest { Profile = profile });
        Assert.Equal(HttpStatusCode.Created, response.StatusCode);
        return Assert.IsType<ManagementClientDraftDetail>(
            await response.Content.ReadFromJsonAsync<ManagementClientDraftDetail>());
    }

    private static async Task<ManagementClientDraftDetail> SaveDraftAsync(
        HttpClient client,
        ManagementClientDraftDetail draft)
    {
        using var response = await client.PutAsJsonAsync(
            $"/api/client-drafts/{draft.Id:D}",
            new SaveClientDraftRequest
            {
                Version = draft.Version,
                CurrentStep = ManagementClientDraftSteps.Review,
                Values = draft.Values,
            });
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        return Assert.IsType<ManagementClientDraftDetail>(
            await response.Content.ReadFromJsonAsync<ManagementClientDraftDetail>());
    }

    private static ManagementRequestContext ContextFor(string subject) => new(
        new ClaimsPrincipal(new ClaimsIdentity(
        [
            new Claim("sub", subject),
            new Claim(ClaimTypes.Name, $"{subject}@tests.local"),
        ], "test")),
        $"test-{subject}");
}
