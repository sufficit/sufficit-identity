using System.Security.Claims;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.AspNetCore.Http;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Caching.Distributed;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging.Abstractions;
using Sufficit.Identity.Core.Data;
using Sufficit.Identity.STS;
using Xunit;

namespace Sufficit.Identity.Tests;

public sealed class SessionTicketCacheRaceTests : IDisposable
{
    private readonly Microsoft.Data.Sqlite.SqliteConnection _connection = new("DataSource=:memory:");
    private readonly ServiceProvider _services;
    private readonly Clock _clock = new();
    private readonly ControlledCache _cache;
    private readonly OidcUserSessionTicketStore _writer;
    private readonly OidcUserSessionTicketStore _revoker;
    private readonly OidcUserSessionRepository _repository;

    public SessionTicketCacheRaceTests()
    {
        _connection.Open();
        var services = new ServiceCollection();
        services.AddDbContextFactory<AppDbContext>(options =>
        {
            options.UseSqlite(_connection);
            options.UseOpenIddict();
        });
        _services = services.BuildServiceProvider();
        var factory = _services.GetRequiredService<IDbContextFactory<AppDbContext>>();
        using var db = factory.CreateDbContext();
        db.Database.EnsureCreated();
        _repository = new OidcUserSessionRepository(factory);
        _cache = new ControlledCache(_clock);
        var protection = new EphemeralDataProtectionProvider();
        var options = new SufficitIdentityOptions
        {
            UserSessions = new() { CacheLifetimeSeconds = 5, CacheOperationTimeoutMilliseconds = 2000 },
        };
        OidcUserSessionTicketStore Store() => new(new OidcUserSessionRepository(factory),
            protection, _cache, new HttpContextAccessor(), options, _clock,
            NullLogger<OidcUserSessionTicketStore>.Instance);
        _writer = Store();
        _revoker = Store();
    }

    [Theory]
    [InlineData("renew", 2)]
    [InlineData("renew", 6)]
    [InlineData("retrieve", 2)]
    [InlineData("retrieve", 6)]
    public async Task Delayed_publication_after_revocation_cannot_restart_the_cache_window(string operation, int delaySeconds)
    {
        var ticket = Ticket();
        var sid = await _writer.StoreAsync(ticket);
        if (operation == "retrieve") _cache.Remove(CacheKey(sid));
        _cache.PauseNextWrite = true;
        var pending = operation == "renew"
            ? _writer.RenewAsync(sid, ticket)
            : (Task)_writer.RetrieveAsync(sid);
        try
        {
            await _cache.WriteEntered.Task.WaitAsync(TimeSpan.FromSeconds(5));
            await _revoker.RemoveAsync(sid);
            Assert.Null(await _repository.FindAsync(sid, default));
            _clock.Advance(TimeSpan.FromSeconds(delaySeconds));
        }
        finally { _cache.ReleaseWrite.TrySetResult(); }
        await pending;
        if (delaySeconds < 5)
        {
            // Best-effort invalidation permits a late entry only inside the original window.
            Assert.NotNull(await _revoker.RetrieveAsync(sid));
            _clock.Advance(TimeSpan.FromSeconds(5 - delaySeconds));
        }
        Assert.Null(await _revoker.RetrieveAsync(sid));
        Assert.Null(await _repository.FindAsync(sid, default));
    }

    [Fact]
    public async Task Failed_invalidation_expires_without_extending_the_window_on_cache_hits()
    {
        var sid = await _writer.StoreAsync(Ticket());
        _cache.FailRemove = true;
        await _revoker.RemoveAsync(sid);
        Assert.Null(await _repository.FindAsync(sid, default));
        _clock.Advance(TimeSpan.FromSeconds(4));
        Assert.NotNull(await _writer.RetrieveAsync(sid));
        _clock.Advance(TimeSpan.FromSeconds(1));
        Assert.Null(await _writer.RetrieveAsync(sid));
    }

    [Fact]
    public async Task Cache_window_never_exceeds_ticket_expiration()
    {
        var ticket = Ticket();
        ticket.Properties.ExpiresUtc = _clock.GetUtcNow().AddSeconds(2);
        var sid = await _writer.StoreAsync(ticket);
        _clock.Advance(TimeSpan.FromSeconds(2));
        Assert.Null(await _cache.GetAsync(CacheKey(sid)));
        Assert.Null(await _revoker.RetrieveAsync(sid));
    }

    private AuthenticationTicket Ticket() => new(new ClaimsPrincipal(new ClaimsIdentity(
        [new Claim("sub", "test-user"), new Claim("sid", "session")], "test")),
        new AuthenticationProperties { ExpiresUtc = _clock.GetUtcNow().AddHours(1) }, "test");

    private static string CacheKey(string sid) => "identity:oidc-session:v1:" + sid;

    private sealed class Clock : TimeProvider
    {
        private DateTimeOffset _now = new(2026, 11, 6, 16, 0, 0, TimeSpan.Zero);
        public override DateTimeOffset GetUtcNow() => _now;
        public void Advance(TimeSpan elapsed) => _now += elapsed;
    }

    // Models provider expiry at write application, including a write arriving
    // after invalidation. Gates avoid timing sleeps; both stores share this cache.
    private sealed class ControlledCache(Clock clock) : IDistributedCache
    {
        private readonly Dictionary<string, (byte[] Data, DateTimeOffset Expiry)> _entries = new();
        public bool PauseNextWrite { get; set; }
        public bool FailRemove { get; set; }
        public TaskCompletionSource WriteEntered { get; } = new(TaskCreationOptions.RunContinuationsAsynchronously);
        public TaskCompletionSource ReleaseWrite { get; } = new(TaskCreationOptions.RunContinuationsAsynchronously);
        public byte[]? Get(string key) =>
            _entries.TryGetValue(key, out var entry) && entry.Expiry > clock.GetUtcNow() ? entry.Data : null;
        public Task<byte[]?> GetAsync(string key, CancellationToken token = default) => Task.FromResult(Get(key));
        public void Set(string key, byte[] value, DistributedCacheEntryOptions options)
        {
            var expiry = options.AbsoluteExpiration ?? DateTimeOffset.MaxValue;
            if (options.AbsoluteExpirationRelativeToNow is { } relative)
                expiry = new[] { expiry, clock.GetUtcNow() + relative }.Min();
            _entries[key] = (value, expiry);
        }
        public async Task SetAsync(string key, byte[] value, DistributedCacheEntryOptions options, CancellationToken token = default)
        {
            if (PauseNextWrite)
            {
                PauseNextWrite = false;
                WriteEntered.TrySetResult();
                await ReleaseWrite.Task.WaitAsync(token);
            }
            token.ThrowIfCancellationRequested();
            Set(key, value, options);
        }
        public void Remove(string key)
        {
            if (FailRemove) throw new IOException("Simulated cache invalidation outage.");
            _entries.Remove(key);
        }
        public Task RemoveAsync(string key, CancellationToken token = default) { Remove(key); return Task.CompletedTask; }
        public void Refresh(string key) { }
        public Task RefreshAsync(string key, CancellationToken token = default) => Task.CompletedTask;
    }

    public void Dispose() { _services.Dispose(); _connection.Dispose(); }
}
