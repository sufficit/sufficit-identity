using System.Net;
using System.Net.Http.Headers;
using System.Net.Http.Json;
using System.Text.Json;
using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.DependencyInjection;
using OpenIddict.Abstractions;
using Sufficit.Identity.Core.Entities;
using Sufficit.Identity.Tests.Infrastructure;
using Xunit;
using static OpenIddict.Abstractions.OpenIddictConstants;

namespace Sufficit.Identity.Tests;

public sealed partial class PersonalTokensTests
{
    [Theory]
    [InlineData(TokenTypeIdentifiers.AccessToken, Statuses.Revoked, 1)]
    [InlineData(TokenTypeIdentifiers.AccessToken, Statuses.Valid, -1)]
    [InlineData(TokenTypeIdentifiers.AccessToken, Statuses.Redeemed, 1)]
    [InlineData("legacy_reference_token", Statuses.Revoked, 1)]
    public async Task Archive_retains_audit_hides_from_list_and_is_idempotent(string type, string status, int expiryDays)
    {
        using var client = _factory.CreateClient();
        client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", await GetAccessTokenAsync(client));
        var id = await SeedArchiveTokenAsync(type, status, expiryDays);
        using var response = await client.PostAsync($"/api/account/tokens/{id}/archive", null);
        Assert.Equal(HttpStatusCode.NoContent, response.StatusCode);
        using var again = await client.PostAsync($"/api/account/tokens/{id}/archive", null);
        Assert.Equal(HttpStatusCode.NoContent, again.StatusCode);
        using var list = JsonDocument.Parse(await client.GetStringAsync("/api/account/tokens"));
        Assert.DoesNotContain(list.RootElement.EnumerateArray(), item => item.GetProperty("key").GetString() == id);
        await using var scope = _factory.Services.CreateAsyncScope();
        var manager = scope.ServiceProvider.GetRequiredService<IOpenIddictTokenManager>();
        var retained = await manager.FindByIdAsync(id);
        Assert.NotNull(retained);
        Assert.Equal(Statuses.Revoked, await manager.GetStatusAsync(retained));
        Assert.True((await manager.GetPropertiesAsync(retained)).ContainsKey("urn:sufficit:token:archived_at"));
        using var update = await client.PatchAsJsonAsync($"/api/account/tokens/{id}", new { updateDescription = true, description = "must not change" });
        Assert.Equal(HttpStatusCode.NotFound, update.StatusCode);
    }

    [Theory]
    [InlineData(Statuses.Valid, 1)]
    [InlineData(Statuses.Valid, 0)]
    [InlineData(Statuses.Inactive, 1)]
    public async Task Archive_does_not_revoke_active_or_ambiguous_tokens(string status, int expiryDays)
    {
        using var client = _factory.CreateClient();
        client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", await GetAccessTokenAsync(client));
        var id = await SeedArchiveTokenAsync(TokenTypeIdentifiers.AccessToken, status, expiryDays);
        using var response = await client.PostAsync($"/api/account/tokens/{id}/archive", null);
        Assert.Equal(HttpStatusCode.Conflict, response.StatusCode);
        await using var scope = _factory.Services.CreateAsyncScope();
        var manager = scope.ServiceProvider.GetRequiredService<IOpenIddictTokenManager>();
        var token = await manager.FindByIdAsync(id);
        Assert.Equal(status, await manager.GetStatusAsync(token!));
        Assert.False((await manager.GetPropertiesAsync(token!)).ContainsKey("urn:sufficit:token:archived_at"));
    }

    [Theory]
    [InlineData(true, TokenTypeIdentifiers.AccessToken, true)]
    [InlineData(false, TokenTypeIdentifiers.RefreshToken, true)]
    [InlineData(false, TokenTypeIdentifiers.AccessToken, false)]
    public async Task Archive_rejects_other_owners_types_and_non_reference_tokens(bool otherOwner, string type, bool reference)
    {
        using var client = _factory.CreateClient();
        client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", await GetAccessTokenAsync(client));
        var id = await SeedArchiveTokenAsync(type, Statuses.Revoked, 1, otherOwner, reference);
        using var response = await client.PostAsync($"/api/account/tokens/{id}/archive", null);
        Assert.Equal(HttpStatusCode.NotFound, response.StatusCode);
    }

    [Fact]
    public async Task Archive_requires_authentication()
    {
        using var client = _factory.CreateClient();
        using var response = await client.PostAsync($"/api/account/tokens/{Guid.NewGuid()}/archive", null);
        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
    }

    private async Task<string> SeedArchiveTokenAsync(string type, string status, int expiryDays, bool otherOwner = false, bool reference = true)
    {
        await using var scope = _factory.Services.CreateAsyncScope();
        var users = scope.ServiceProvider.GetRequiredService<UserManager<ApplicationUser>>();
        var user = await users.FindByNameAsync(TestDataSeeder.DefaultUsername);
        var manager = scope.ServiceProvider.GetRequiredService<IOpenIddictTokenManager>();
        var token = await manager.CreateAsync(new OpenIddictTokenDescriptor
        {
            CreationDate = DateTimeOffset.UtcNow.AddDays(-5),
            ExpirationDate = expiryDays == 0 ? null : DateTimeOffset.UtcNow.AddDays(expiryDays),
            ReferenceId = reference ? $"archive-test-{Guid.NewGuid():N}" : null,
            Subject = otherOwner ? Guid.NewGuid().ToString() : user!.Id,
            Type = type,
            Status = status
        });
        return (await manager.GetIdAsync(token))!;
    }
}
