using System.Data.Common;
using Microsoft.EntityFrameworkCore.Diagnostics;
using System.Security.Claims;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.AspNetCore.Http;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Caching.Distributed;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging.Abstractions;
using Sufficit.Identity.Core.Data;
using Sufficit.Identity.Core.Entities;
using Sufficit.Identity.STS;
using Xunit;

namespace Sufficit.Identity.Tests;

public sealed class OidcUserSessionRepositoryTests : IDisposable
{
    private readonly Microsoft.Data.Sqlite.SqliteConnection _connection = new("DataSource=:memory:");
    private readonly DeleteInterceptor _interceptor = new();
    private readonly ServiceProvider _services;
    private readonly OidcUserSessionRepository _repository;
    private static readonly DateTime Initial = new(2026, 11, 6, 10, 0, 0, DateTimeKind.Utc);

    public OidcUserSessionRepositoryTests()
    {
        _connection.Open();
        var services = new ServiceCollection();
        services.AddDistributedMemoryCache();
        services.AddDbContextFactory<AppDbContext>(options =>
        {
            options.UseSqlite(_connection);
            options.AddInterceptors(_interceptor);
            options.UseOpenIddict();
        });
        _services = services.BuildServiceProvider();
        var factory = _services.GetRequiredService<IDbContextFactory<AppDbContext>>();
        using var db = factory.CreateDbContext();
        db.Database.EnsureCreated();
        _repository = new OidcUserSessionRepository(factory);
    }

    [Fact]
    public async Task Renewal_preserves_creation_and_device_metadata_while_replacing_ticket_and_expiry()
    {
        await _repository.UpsertAsync(Session("sid", "user"), default);
        var renewed = Session("sid", "user");
        renewed.CreatedAtUtc = Initial.AddHours(1);
        renewed.LastActivityUtc = Initial.AddHours(1);
        renewed.RemoteIpAddress = "198.51.100.9";
        renewed.UserAgent = "different-device";
        renewed.ProtectedTicket = [4, 5, 6];
        renewed.ExpiresUtc = Initial.AddDays(2);
        Assert.True(await _repository.RenewAsync(renewed, default));
        var persisted = Assert.IsType<OidcUserSession>(await _repository.FindAsync("sid", default));
        Assert.Equal(Initial, persisted.CreatedAtUtc);
        Assert.Equal("192.0.2.1", persisted.RemoteIpAddress);
        Assert.Equal("original-device", persisted.UserAgent);
        Assert.Equal(renewed.LastActivityUtc, persisted.LastActivityUtc);
        Assert.Equal(renewed.ExpiresUtc, persisted.ExpiresUtc);
        Assert.Equal(renewed.ProtectedTicket, persisted.ProtectedTicket);
        Assert.Single(await _repository.ListBySubjectAsync("user", "sid", default));
    }

    [Fact]
    public async Task Activity_touch_does_not_overwrite_a_newer_ticket_or_recreate_a_deleted_session()
    {
        await _repository.UpsertAsync(Session("sid", "user"), default);
        var snapshot = (await _repository.FindAsync("sid", default))!;
        var renewed = Session("sid", "user");
        renewed.ProtectedTicket = [9];
        Assert.True(await _repository.RenewAsync(renewed, default));
        await _repository.TouchAsync(snapshot, Initial.AddMinutes(2), default);
        Assert.Equal(new byte[] { 9 }, (await _repository.FindAsync("sid", default))!.ProtectedTicket);
        await _repository.DeleteAsync("sid", default);
        await _repository.TouchAsync(snapshot, Initial.AddMinutes(3), default);
        Assert.Null(await _repository.FindAsync("sid", default));
    }

    [Fact]
    public async Task Subject_deletion_preserves_the_exception_and_other_users_and_returns_cache_keys()
    {
        await _repository.UpsertAsync(Session("keep", "user"), default);
        await _repository.UpsertAsync(Session("drop", "user"), default);
        await _repository.UpsertAsync(Session("other", "other-user"), default);
        var deleted = await _repository.DeleteBySubjectAsync("user", "keep", default);
        Assert.Equal(1, deleted.Removed);
        Assert.Equal("drop", Assert.Single(deleted.SessionIds));
        var current = Assert.Single(await _repository.ListBySubjectAsync("user", "keep", default));
        Assert.True(current.IsCurrent);
        Assert.Equal("keep", current.SessionId);
        Assert.NotNull(await _repository.FindAsync("other", default));
        Assert.Null(await _repository.FindAsync("drop", default));
    }

    [Theory]
    [InlineData(true)]
    [InlineData(false)]
    public async Task Ticket_store_discards_expired_or_corrupt_database_tickets(bool expired)
    {
        var row = Session("discard", "user");
        row.ExpiresUtc = expired ? DateTime.UtcNow.AddMinutes(-1) : DateTime.UtcNow.AddHours(1);
        await _repository.UpsertAsync(row, default);
        var store = new OidcUserSessionTicketStore(_repository,
            new EphemeralDataProtectionProvider(), _services.GetRequiredService<IDistributedCache>(),
            new HttpContextAccessor(), new SufficitIdentityOptions(), TimeProvider.System,
            NullLogger<OidcUserSessionTicketStore>.Instance);
        Assert.Null(await store.RetrieveAsync("discard", default(CancellationToken)));
        Assert.Null(await _repository.FindAsync("discard", default));
    }

    [Fact]
    public async Task Late_renewal_after_revocation_does_not_recreate_database_or_cache_ticket()
    {
        var cache = _services.GetRequiredService<IDistributedCache>();
        var store = new OidcUserSessionTicketStore(_repository,
            new EphemeralDataProtectionProvider(), cache,
            new HttpContextAccessor(), new SufficitIdentityOptions(), TimeProvider.System,
            NullLogger<OidcUserSessionTicketStore>.Instance);
        var ticket = new AuthenticationTicket(new ClaimsPrincipal(new ClaimsIdentity(
            [new Claim("sub", "test-user"), new Claim("sid", "late-renewal")], "test")),
            new AuthenticationProperties { ExpiresUtc = DateTimeOffset.UtcNow.AddHours(1) }, "test");
        var sid = await store.StoreAsync(ticket);
        await store.RemoveAsync(sid);
        await store.RenewAsync(sid, ticket);
        Assert.Null(await _repository.FindAsync(sid, default));
        Assert.Null(await cache.GetAsync("identity:oidc-session:v1:" + sid));
        Assert.Null(await store.RetrieveAsync(sid));
    }

    [Fact]
    public async Task Renewal_cannot_change_the_session_owner()
    {
        await _repository.UpsertAsync(Session("sid", "original-user"), default);
        Assert.False(await _repository.RenewAsync(Session("sid", "other-user"), default));
        var stored = (await _repository.FindAsync("sid", default))!;
        Assert.Equal("original-user", stored.Subject);
        Assert.Equal(new byte[] { 1, 2, 3 }, stored.ProtectedTicket);
    }

    [Theory]
    [InlineData("insert")]
    [InlineData("delete")]
    [InlineData("replace")]
    public async Task Bulk_revocation_deletes_only_the_selected_row_snapshot(string concurrentChange)
    {
        await _repository.UpsertAsync(Session("selected", "user"), default);
        _interceptor.BeforeDelete = async () =>
        {
            if (concurrentChange != "insert") await _repository.DeleteAsync("selected", default);
            if (concurrentChange != "delete")
                await _repository.UpsertAsync(Session(
                    concurrentChange == "replace" ? "selected" : "new-session", "user"), default);
        };
        var result = await _repository.DeleteBySubjectAsync("user", null, default);
        Assert.Equal(concurrentChange == "insert" ? 1 : 0, result.Removed);
        Assert.Equal("selected", Assert.Single(result.SessionIds));
        var remaining = await _repository.ListBySubjectAsync("user", null, default);
        if (concurrentChange == "delete") Assert.Empty(remaining);
        else Assert.Equal(concurrentChange == "replace" ? "selected" : "new-session",
            Assert.Single(remaining).SessionId);
    }

    private sealed class DeleteInterceptor : DbCommandInterceptor
    {
        public Func<Task>? BeforeDelete { get; set; }
        public override async ValueTask<InterceptionResult<int>> NonQueryExecutingAsync(
            DbCommand command, CommandEventData eventData, InterceptionResult<int> result,
            CancellationToken cancellationToken = default)
        {
            if (command.CommandText.TrimStart().StartsWith("DELETE", StringComparison.OrdinalIgnoreCase)
                && BeforeDelete is { } action)
            {
                BeforeDelete = null;
                await action();
            }
            return result;
        }
    }

    private static OidcUserSession Session(string sid, string subject) => new()
    {
        SessionId = sid, Subject = subject, CreatedAtUtc = Initial,
        LastActivityUtc = Initial, ExpiresUtc = Initial.AddDays(1),
        ProtectedTicket = [1, 2, 3], RemoteIpAddress = "192.0.2.1", UserAgent = "original-device",
    };

    public void Dispose()
    {
        _services.Dispose();
        _connection.Dispose();
    }
}
