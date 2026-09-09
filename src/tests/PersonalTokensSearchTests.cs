using System.Net;
using System.Net.Http.Headers;
using System.Net.Http.Json;
using System.Text.Json;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using OpenIddict.EntityFrameworkCore.Models;
using Sufficit.Identity.Core.Data;
using Sufficit.Identity.STS.Controllers;
using Xunit;

namespace Sufficit.Identity.Tests;

public sealed partial class PersonalTokensTests
{
    [Fact]
    public async Task Search_is_owner_scoped_bounded_and_excludes_session_tokens()
    {
        await using var scope = _factory.Services.CreateAsyncScope();
        var db = scope.ServiceProvider.GetRequiredService<AppDbContext>();
        var owner = Guid.NewGuid().ToString();
        var other = Guid.NewGuid().ToString();
        var rows = Enumerable.Range(0, 6118).Select(i => SearchRow(owner, $"fixture-{i:D5}")).ToArray();
        db.AddRange(rows);
        db.Add(SearchRow(other, "foreign-token"));
        var session = SearchRow(owner, "session-token");
        session.Properties = "{}";
        db.Add(session);
        await db.SaveChangesAsync();
        db.ChangeTracker.Clear();
        var first = await PersonalTokenSearch.ReadAsync(db, owner, 0, 25, "active", null, default);
        Assert.Equal(25, first.Items.Count);
        Assert.NotNull(first.NextOffset);
        Assert.All(first.Items, t => Assert.Equal(Guid.Parse(owner), t.SubjectId));
        Assert.DoesNotContain(first.Items, t => t.Description == "session-token");
        var second = await PersonalTokenSearch.ReadAsync(db, owner, first.NextOffset!.Value, 25, "active", null, default);
        Assert.Empty(first.Items.Select(t => t.Key).Intersect(second.Items.Select(t => t.Key)));
        Assert.Empty(db.ChangeTracker.Entries<OpenIddictEntityFrameworkCoreToken>());
        Assert.DoesNotContain("secret-payload", JsonSerializer.Serialize(first));
        Assert.DoesNotContain("secret-reference", JsonSerializer.Serialize(first));
    }

    [Fact]
    public async Task Search_filters_history_legacy_archived_and_replaced_records()
    {
        await using var scope = _factory.Services.CreateAsyncScope();
        var db = scope.ServiceProvider.GetRequiredService<AppDbContext>();
        var owner = Guid.NewGuid().ToString();
        var active = SearchRow(owner, "Em uso");
        var expired = SearchRow(owner, "Expirado"); expired.ExpirationDate = DateTime.UtcNow.AddDays(-1);
        var revoked = SearchRow(owner, "Revogado"); revoked.Status = "revoked";
        var legacy = SearchRow(owner, "Legado"); legacy.Type = "legacy_reference_token";
        var archived = SearchRow(owner, "Arquivado", ("archived_at", DateTimeOffset.UtcNow.ToString("O")));
        var replaced = SearchRow(owner, "Substituído"); replaced.Type = "legacy_reference_token";
        var replacement = SearchRow(owner, "Novo", ("replaces_id", replaced.Id!));
        db.AddRange(active, expired, revoked, legacy, archived, replaced, replacement);
        await db.SaveChangesAsync(); db.ChangeTracker.Clear();
        var history = await PersonalTokenSearch.ReadAsync(db, owner, 0, 25, "history", null, default);
        Assert.Equal(3, history.Items.Count);
        Assert.Contains(history.Items, t => t.Key == legacy.Id);
        Assert.DoesNotContain(history.Items, t => t.Key == archived.Id || t.Key == replaced.Id);
        var found = await PersonalTokenSearch.ReadAsync(db, owner, 0, 25, "all", "em USO", default);
        Assert.Equal(active.Id, Assert.Single(found.Items).Key);
        var old = await PersonalTokenSearch.ReadAsync(db, owner, 0, 25, "legacy", null, default);
        Assert.Equal(legacy.Id, Assert.Single(old.Items).Key);
    }

    [Fact]
    public async Task Search_limits_scan_even_when_nothing_matches()
    {
        await using var scope = _factory.Services.CreateAsyncScope();
        var db = scope.ServiceProvider.GetRequiredService<AppDbContext>();
        var owner = Guid.NewGuid().ToString();
        db.AddRange(Enumerable.Range(0, 2100).Select(i => SearchRow(owner, $"row-{i}")));
        await db.SaveChangesAsync(); db.ChangeTracker.Clear();
        var page = await PersonalTokenSearch.ReadAsync(db, owner, 0, 25, "all", "no-such-description", default);
        Assert.Empty(page.Items);
        Assert.Equal(PersonalTokenSearch.ScanLimit, page.NextOffset);
        var last = await PersonalTokenSearch.ReadAsync(db, owner, page.NextOffset!.Value, 25, "all", "no-such-description", default);
        Assert.Empty(last.Items);
        Assert.Null(last.NextOffset);
    }

    [Fact]
    public async Task Search_endpoint_requires_authentication_and_rejects_unbounded_sizes()
    {
        using var client = _factory.CreateClient();
        Assert.Equal(HttpStatusCode.Unauthorized, (await client.GetAsync("/api/account/tokens/search")).StatusCode);
        client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", await GetAccessTokenAsync(client));
        foreach (var query in new[] { "pageSize=0", "pageSize=6118", "offset=-1", "state=unknown" })
            Assert.Equal(HttpStatusCode.BadRequest, (await client.GetAsync("/api/account/tokens/search?" + query)).StatusCode);
        var result = await client.GetFromJsonAsync<PersonalTokenPage>("/api/account/tokens/search?pageSize=1");
        Assert.NotNull(result);
        Assert.InRange(result.Items.Count, 0, 1);
        Assert.All(result.Items, t => Assert.Equal(result.SubjectId, t.SubjectId.ToString()));
    }

    private static OpenIddictEntityFrameworkCoreToken SearchRow(string owner, string description, params (string Key, string Value)[] extra)
    {
        var props = new Dictionary<string, string> { ["urn:sufficit:token:client_id"] = "SufficitAPIUserAccess",
            ["urn:sufficit:token:description"] = description };
        foreach (var (key, value) in extra) props["urn:sufficit:token:" + key] = value;
        return new() { Id = Guid.NewGuid().ToString(), Subject = owner, Type = OpenIddict.Abstractions.OpenIddictConstants.TokenTypeIdentifiers.AccessToken, Status = "valid",
            CreationDate = DateTime.UtcNow.AddDays(-3), ExpirationDate = DateTime.UtcNow.AddDays(1),
            ReferenceId = "secret-reference-" + Guid.NewGuid(), Payload = "secret-payload",
            Properties = JsonSerializer.Serialize(props) };
    }

    [Fact]
    public async Task Lookup_returns_only_selected_owned_personal_tokens_and_enforces_limit()
    {
        using var client = _factory.CreateClient();
        client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", await GetAccessTokenAsync(client));
        using var created = await client.PostAsJsonAsync("/api/account/tokens", new { description = "lookup-personal-test" });
        Assert.Equal(HttpStatusCode.Created, created.StatusCode);
        var token = await created.Content.ReadFromJsonAsync<PersonalTokenCreated>();
        await using var scope = _factory.Services.CreateAsyncScope();
        var db = scope.ServiceProvider.GetRequiredService<AppDbContext>();
        var other = SearchRow(Guid.NewGuid().ToString(), "foreign-lookup");
        var persisted = await db.Set<OpenIddictEntityFrameworkCoreToken>().AsNoTracking()
            .Where(t => t.Id == token!.Token.Key).Select(t => new { t.Subject, t.Type, t.Properties, HasReference = t.ReferenceId != null }).SingleAsync();
        Assert.True(persisted.HasReference);
        Assert.Equal(token!.Token.SubjectId.ToString(), persisted.Subject);
        Assert.Contains("SufficitAPIUserAccess", persisted.Properties);
        using var metadata = JsonDocument.Parse(persisted.Properties!);
        Assert.Equal("SufficitAPIUserAccess", metadata.RootElement.GetProperty("urn:sufficit:token:client_id").GetString());
        var direct = await PersonalTokenSearch.ReadAsync(db, persisted.Subject!, 0, 100, "all", null, default, [token.Token.Key]);
        Assert.Equal("access_token", Assert.Single(direct.Items).Type);
        db.Add(other); await db.SaveChangesAsync();
        using var result = await client.PostAsJsonAsync("/api/account/tokens/lookup", new[] { token!.Token.Key, other.Id! });
        Assert.Equal(HttpStatusCode.OK, result.StatusCode);
        var selected = await result.Content.ReadFromJsonAsync<PersonalTokenSummary[]>();
        Assert.Equal(token.Token.Key, Assert.Single(selected!).Key);
        Assert.Equal(HttpStatusCode.BadRequest, (await client.PostAsJsonAsync("/api/account/tokens/lookup",
            Enumerable.Range(0, 101).Select(i => i.ToString()).ToArray())).StatusCode);
    }
}
