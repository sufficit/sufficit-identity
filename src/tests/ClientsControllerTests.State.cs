using System.Net;
using System.Net.Http.Json;
using System.Text.Json;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using OpenIddict.EntityFrameworkCore.Models;
using Sufficit.Identity.Core.Data;
using Sufficit.Identity.Management.Controllers;
using Sufficit.Identity.Tests.Infrastructure;
using Xunit;
using static OpenIddict.Abstractions.OpenIddictConstants;

namespace Sufficit.Identity.Tests;

public sealed partial class ClientsControllerTests
{
    [Fact]
    public async Task Disabling_a_client_refuses_it_revokes_its_tokens_and_is_audited_until_re_enabled()
    {
        using var factory = new ManagementTestFactory();
        await ((IAsyncLifetime)factory).InitializeAsync();
        var client = factory.CreateClient();
        var clientId = $"cc-state-{Guid.NewGuid():N}";
        var secret = $"secret-{Guid.NewGuid():N}";
        using (var created = await client.PostAsJsonAsync("/api/clients", new CreateClientRequest
        {
            ClientId = clientId,
            ClientSecret = secret,
            DisplayName = "State client",
            GrantTypes = ["client_credentials"],
            Scopes = [TestDataSeeder.ScopeName],
        }))
            Assert.Equal(HttpStatusCode.Created, created.StatusCode);
        Assert.Equal(HttpStatusCode.OK, await RequestClientCredentialsTokenAsync(client, clientId, secret));

        using (var missingReason = await SetStateAsync(client, clientId, new SetClientStateRequest { Enabled = false }))
            Assert.Equal(HttpStatusCode.BadRequest, missingReason.StatusCode);

        using (var disabled = await SetStateAsync(client, clientId,
            new SetClientStateRequest { Enabled = false, Reason = "secret leaked", RevokeTokens = true }))
        {
            Assert.Equal(HttpStatusCode.OK, disabled.StatusCode);
            var detail = await disabled.Content.ReadFromJsonAsync<JsonElement>();
            Assert.Equal("disabled", detail.GetProperty("status").GetString());
            Assert.Equal("secret leaked", detail.GetProperty("disabledReason").GetString());
        }
        Assert.Equal(HttpStatusCode.BadRequest, await RequestClientCredentialsTokenAsync(client, clientId, secret));

        using (var page = await client.GetAsync($"/api/clients?q={clientId}&status=disabled"))
        {
            var body = await page.Content.ReadFromJsonAsync<JsonElement>();
            var item = Assert.Single(body.GetProperty("items").EnumerateArray());
            Assert.Equal("disabled", item.GetProperty("status").GetString());
        }

        await using (var scope = factory.Services.CreateAsyncScope())
        {
            var database = scope.ServiceProvider.GetRequiredService<AppDbContext>();
            var application = await database.Set<OpenIddictEntityFrameworkCoreApplication>()
                .AsNoTracking().SingleAsync(entry => entry.ClientId == clientId);
            Assert.DoesNotContain(await database.Set<OpenIddictEntityFrameworkCoreToken>().AsNoTracking()
                    .Where(token => EF.Property<string?>(token, "ApplicationId") == application.Id)
                    .Select(token => token.Status).ToListAsync(),
                status => status == Statuses.Valid);
            var audit = await database.ManagementAuditEvents.AsNoTracking()
                .SingleAsync(entry => entry.ResourceId == clientId && entry.ReasonCode == "client_disabled");
            Assert.Contains("secret leaked", audit.AfterJson);
        }

        using (var enabled = await SetStateAsync(client, clientId, new SetClientStateRequest { Enabled = true }))
            Assert.Equal("active", (await enabled.Content.ReadFromJsonAsync<JsonElement>()).GetProperty("status").GetString());
        Assert.Equal(HttpStatusCode.OK, await RequestClientCredentialsTokenAsync(client, clientId, secret));
    }

    private static Task<HttpResponseMessage> SetStateAsync(HttpClient client, string clientId, SetClientStateRequest request) =>
        client.PostAsJsonAsync($"/api/clients/state?clientId={Uri.EscapeDataString(clientId)}", request);
}
