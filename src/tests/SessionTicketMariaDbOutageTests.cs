using System.Diagnostics;
using System.Security.Claims;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.AspNetCore.Http;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Caching.Distributed;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging.Abstractions;
using MySqlConnector;
using Sufficit.Identity.Core.Data;
using Sufficit.Identity.STS;
using Xunit;

namespace Sufficit.Identity.Tests;

public sealed class SessionTicketMariaDbOutageTests
{
    public sealed class LocalMariaDbFactAttribute : FactAttribute
    {
        public LocalMariaDbFactAttribute()
        {
            if (Environment.GetEnvironmentVariable("SUFFICIT_TEST_MARIADB_DOCKER") != "1")
                Skip = "Set SUFFICIT_TEST_MARIADB_DOCKER=1 to run the owned disposable MariaDB container.";
        }
    }

    [LocalMariaDbFact]
    [Trait("Category", "MariaDbIntegration")]
    public async Task Database_outage_preserves_warm_cache_but_rejects_cold_reads_and_mutations_until_recovery()
    {
        await using var server = new LocalMariaDb();
        await server.CreateAsync();
        var services = new ServiceCollection();
        services.AddDistributedMemoryCache();
        services.AddDbContextFactory<AppDbContext>(options =>
        {
            options.UseMySql(server.ConnectionString, new MariaDbServerVersion(new Version(10, 11)));
            options.UseOpenIddict();
        });
        using var provider = services.BuildServiceProvider();
        var factory = provider.GetRequiredService<IDbContextFactory<AppDbContext>>();
        await using (var db = await factory.CreateDbContextAsync())
            await db.Database.EnsureCreatedAsync();
        var repository = new OidcUserSessionRepository(factory);
        var cache = provider.GetRequiredService<IDistributedCache>();
        var store = new OidcUserSessionTicketStore(repository, new EphemeralDataProtectionProvider(),
            cache, new HttpContextAccessor(), new SufficitIdentityOptions
            {
                UserSessions = new() { CacheLifetimeSeconds = 300 },
            }, TimeProvider.System, NullLogger<OidcUserSessionTicketStore>.Instance);
        var ticket = Ticket("retained");
        var sid = await store.StoreAsync(ticket);
        ticket.Properties.ExpiresUtc = DateTimeOffset.UtcNow.AddHours(2);
        await store.RenewAsync(sid, ticket);
        Assert.Equal(ticket.Properties.ExpiresUtc.Value.UtcDateTime,
            (await repository.FindAsync(sid, default))!.ExpiresUtc);
        await store.StoreAsync(Ticket("drop"));
        // Exercise the selected-row Contains translation on the real provider.
        Assert.Equal(1, await store.RevokeAllBySubjectAsync("test-user", sid));
        Assert.Null(await store.RetrieveAsync("drop"));

        await server.StopAsync();
        Assert.NotNull(await store.RetrieveAsync(sid));
        await AssertDatabaseUnavailableAsync(() => store.RemoveAsync(sid));
        await AssertDatabaseUnavailableAsync(() => store.RenewAsync(sid, ticket));
        await AssertDatabaseUnavailableAsync(() => store.StoreAsync(Ticket("uncommitted")));
        Assert.Null(await cache.GetAsync(Key("uncommitted")));
        // Failed revocation is reported, and must not masquerade as a committed delete.
        Assert.NotNull(await cache.GetAsync(Key(sid)));
        await cache.RemoveAsync(Key(sid));
        await AssertDatabaseUnavailableAsync(() => store.RetrieveAsync(sid));

        await server.RestartAsync();
        Assert.NotNull(await repository.FindAsync(sid, default));
        Assert.Null(await repository.FindAsync("uncommitted", default));
        Assert.NotNull(await store.RetrieveAsync(sid));
        await store.RemoveAsync(sid);
        Assert.Null(await repository.FindAsync(sid, default));
        Assert.Null(await store.RetrieveAsync(sid));
    }

    private static async Task AssertDatabaseUnavailableAsync(Func<Task> operation)
    {
        var error = await Record.ExceptionAsync(operation);
        Assert.NotNull(error);
        // Pomelo may wrap a connector failure in its execution strategy.
        Assert.IsType<MySqlException>(error.GetBaseException());
    }

    private static AuthenticationTicket Ticket(string sid) => new(new ClaimsPrincipal(new ClaimsIdentity(
        [new Claim("sub", "test-user"), new Claim("sid", sid)], "test")),
        new AuthenticationProperties { ExpiresUtc = DateTimeOffset.UtcNow.AddHours(1) }, "test");
    private static string Key(string sid) => "identity:oidc-session:v1:" + sid;

    private sealed class LocalMariaDb : IAsyncDisposable
    {
        private readonly string _name = "identity-session-test-" + Guid.NewGuid().ToString("N");
        private bool _created;
        public string ConnectionString { get; private set; } = "";

        public async Task CreateAsync()
        {
            using var listener = new System.Net.Sockets.TcpListener(System.Net.IPAddress.Loopback, 0);
            listener.Start();
            var port = ((System.Net.IPEndPoint)listener.LocalEndpoint).Port;
            listener.Stop();
            await DockerAsync("create", "--name", _name, "--publish", $"127.0.0.1:{port}:3306",
                "--env", "MARIADB_RANDOM_ROOT_PASSWORD=yes", "--env", "MARIADB_DATABASE=session_test",
                "--env", "MARIADB_USER=session_test", "--env", "MARIADB_PASSWORD=disposable-test-only",
                "mariadb:10.11");
            _created = true;
            await DockerAsync("start", _name);
            await SetConnectionAndWaitAsync();
        }

        public Task StopAsync() => DockerAsync("stop", "--time", "1", _name);
        public async Task RestartAsync()
        {
            await DockerAsync("start", _name);
            await SetConnectionAndWaitAsync();
        }

        private async Task SetConnectionAndWaitAsync()
        {
            var endpoint = (await DockerAsync("port", _name, "3306/tcp")).Trim();
            Assert.StartsWith("127.0.0.1:", endpoint);
            var port = int.Parse(endpoint.Split(':')[1]);
            ConnectionString = $"Server=127.0.0.1;Port={port};Database=session_test;User=session_test;" +
                "Password=disposable-test-only;Pooling=false;Connection Timeout=1;Default Command Timeout=3";
            using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(60));
            while (true)
            {
                try
                {
                    await using var connection = new MySqlConnection(ConnectionString);
                    await connection.OpenAsync(timeout.Token);
                    return;
                }
                catch (MySqlException) { await Task.Delay(200, timeout.Token); }
            }
        }

        private static async Task<string> DockerAsync(params string[] arguments)
        {
            var start = new ProcessStartInfo("docker")
            {
                UseShellExecute = false, RedirectStandardOutput = true, RedirectStandardError = true,
            };
            foreach (var argument in arguments) start.ArgumentList.Add(argument);
            using var process = Process.Start(start)!;
            var output = process.StandardOutput.ReadToEndAsync();
            var error = process.StandardError.ReadToEndAsync();
            using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(60));
            await process.WaitForExitAsync(timeout.Token);
            Assert.True(process.ExitCode == 0, await error);
            return await output;
        }

        public async ValueTask DisposeAsync()
        {
            if (_created) await DockerAsync("rm", "--force", "--volumes", _name);
        }
    }
}
