using System.Security.Claims;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.AspNetCore.Http;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Caching.Distributed;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.DependencyInjection;
using Sufficit.Identity.Core.Data;
using Sufficit.Identity.STS;
using Xunit;

namespace Sufficit.Identity.Tests;

public sealed class SessionTicketCancellationTests
{
    [Theory]
    [InlineData("store")]
    [InlineData("renew")]
    [InlineData("retrieve")]
    [InlineData("remove")]
    public async Task Explicit_cancellation_reaches_database_creation(string operation)
    {
        using var cancellation = new CancellationTokenSource();
        var factory = new WaitingFactory();
        ITicketStore store = Store(factory, new TestCache());
        var task = Invoke(store, operation, cancellation.Token);
        await factory.Entered.Task.WaitAsync(TimeSpan.FromSeconds(5));
        cancellation.Cancel();
        try
        {
            await Assert.ThrowsAnyAsync<OperationCanceledException>(() => task.WaitAsync(TimeSpan.FromSeconds(2)));
        }
        finally { factory.Stop.TrySetResult(); await Observe(task); }
    }

    [Theory]
    [InlineData("store")]
    [InlineData("renew")]
    [InlineData("retrieve")]
    [InlineData("remove")]
    public async Task Context_abort_is_honored_even_without_an_explicit_token(string operation)
    {
        using var cancellation = new CancellationTokenSource();
        var context = new DefaultHttpContext { RequestAborted = cancellation.Token };
        var factory = new WaitingFactory();
        ITicketStore store = Store(factory, new TestCache());
        var task = Invoke(store, operation, default, context);
        await factory.Entered.Task.WaitAsync(TimeSpan.FromSeconds(5));
        cancellation.Cancel();
        try
        {
            await Assert.ThrowsAnyAsync<OperationCanceledException>(() => task.WaitAsync(TimeSpan.FromSeconds(2)));
        }
        finally { factory.Stop.TrySetResult(); await Observe(task); }
    }

    [Fact]
    public async Task Cache_read_cancellation_does_not_fall_back_to_database()
    {
        using var cancellation = new CancellationTokenSource();
        var factory = new WaitingFactory();
        var cache = new TestCache { WaitOnRead = true };
        ITicketStore store = Store(factory, cache);
        var task = store.RetrieveAsync("session", cancellation.Token);
        await cache.Entered.Task.WaitAsync(TimeSpan.FromSeconds(5));
        cancellation.Cancel();
        try
        {
            await Assert.ThrowsAnyAsync<OperationCanceledException>(() => task.WaitAsync(TimeSpan.FromSeconds(2)));
            Assert.False(factory.Entered.Task.IsCompleted);
        }
        finally { factory.Stop.TrySetResult(); await Observe(task); }
    }

    [Theory]
    [InlineData("store")]
    [InlineData("renew")]
    [InlineData("remove")]
    public async Task Cancellation_during_cache_mutation_propagates_without_undoing_database_commit(string operation)
    {
        using var connection = new Microsoft.Data.Sqlite.SqliteConnection("DataSource=:memory:");
        await connection.OpenAsync();
        var services = new ServiceCollection();
        services.AddDbContextFactory<AppDbContext>(options =>
        {
            options.UseSqlite(connection);
            options.UseOpenIddict();
        });
        using var provider = services.BuildServiceProvider();
        var factory = provider.GetRequiredService<IDbContextFactory<AppDbContext>>();
        await using (var database = await factory.CreateDbContextAsync())
            await database.Database.EnsureCreatedAsync();
        var cache = new TestCache();
        ITicketStore store = Store(factory, cache);
        if (operation != "store") await Invoke(store, "store", default);
        cache.WaitOnWrite = operation != "remove";
        cache.WaitOnRemove = operation == "remove";
        using var cancellation = new CancellationTokenSource();
        var task = Invoke(store, operation, cancellation.Token);
        await cache.MutationEntered.Task.WaitAsync(TimeSpan.FromSeconds(5));
        cancellation.Cancel();
        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => task.WaitAsync(TimeSpan.FromSeconds(2)));
        await using var after = await factory.CreateDbContextAsync();
        Assert.Equal(operation == "remove" ? 0 : 1, await after.OidcUserSessions.CountAsync());
    }

    private static OidcUserSessionTicketStore Store(IDbContextFactory<AppDbContext> factory, TestCache cache) =>
        new(factory, new EphemeralDataProtectionProvider(), cache, new HttpContextAccessor(),
            new SufficitIdentityOptions(), TimeProvider.System, NullLogger<OidcUserSessionTicketStore>.Instance);

    private static Task Invoke(ITicketStore store, string operation, CancellationToken token, HttpContext? context = null)
    {
        var ticket = new AuthenticationTicket(new ClaimsPrincipal(new ClaimsIdentity(
            [new Claim("sub", "test-user"), new Claim("sid", "session")], "test")), "test");
        return (operation, context) switch
        {
            ("store", null) => store.StoreAsync(ticket, token),
            ("renew", null) => store.RenewAsync("session", ticket, token),
            ("retrieve", null) => store.RetrieveAsync("session", token),
            ("remove", null) => store.RemoveAsync("session", token),
            ("store", _) => store.StoreAsync(ticket, context!, token),
            ("renew", _) => store.RenewAsync("session", ticket, context!, token),
            ("retrieve", _) => store.RetrieveAsync("session", context!, token),
            ("remove", _) => store.RemoveAsync("session", context!, token),
            _ => throw new ArgumentOutOfRangeException(nameof(operation)),
        };
    }

    private static async Task Observe(Task task)
    {
        try { await task; } catch (OperationCanceledException) { }
    }

    private sealed class WaitingFactory : IDbContextFactory<AppDbContext>
    {
        public TaskCompletionSource Entered { get; } = new(TaskCreationOptions.RunContinuationsAsynchronously);
        public TaskCompletionSource Stop { get; } = new(TaskCreationOptions.RunContinuationsAsynchronously);
        public AppDbContext CreateDbContext() => throw new NotSupportedException();
        public async Task<AppDbContext> CreateDbContextAsync(CancellationToken cancellationToken = default)
        {
            Entered.TrySetResult();
            await Stop.Task.WaitAsync(cancellationToken);
            throw new OperationCanceledException("Test cleanup");
        }
    }

    private sealed class TestCache : IDistributedCache
    {
        public bool WaitOnRead { get; init; }
        public bool WaitOnWrite { get; set; }
        public bool WaitOnRemove { get; set; }
        public TaskCompletionSource MutationEntered { get; } = new(TaskCreationOptions.RunContinuationsAsynchronously);
        public TaskCompletionSource Entered { get; } = new(TaskCreationOptions.RunContinuationsAsynchronously);
        public byte[]? Get(string key) => null;
        public async Task<byte[]?> GetAsync(string key, CancellationToken token = default)
        {
            Entered.TrySetResult();
            if (WaitOnRead) await Task.Delay(Timeout.InfiniteTimeSpan, token);
            return null;
        }
        public void Refresh(string key) { }
        public Task RefreshAsync(string key, CancellationToken token = default) => Task.CompletedTask;
        public void Remove(string key) { }
        public Task RemoveAsync(string key, CancellationToken token = default) => WaitOnRemove ? WaitForCancellation(token) : Task.CompletedTask;
        public void Set(string key, byte[] value, DistributedCacheEntryOptions options) { }
        public Task SetAsync(string key, byte[] value, DistributedCacheEntryOptions options, CancellationToken token = default) => WaitOnWrite ? WaitForCancellation(token) : Task.CompletedTask;
        private async Task WaitForCancellation(CancellationToken token)
        {
            MutationEntered.TrySetResult();
            await Task.Delay(Timeout.InfiniteTimeSpan, token);
        }
    }
}
