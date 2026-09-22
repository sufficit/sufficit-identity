using System.Data.Common;
using System.Net;
using System.Security.Claims;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.TestHost;
using Microsoft.Data.Sqlite;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Diagnostics;
using Microsoft.Extensions.DependencyInjection;
using Sufficit.Identity.Core.Data;
using Sufficit.Identity.Core.Entities;
using Sufficit.Identity.Core.Services;
using Sufficit.Identity.UI.Management;
using Xunit;

namespace Sufficit.Identity.Tests;

public sealed partial class ManagementUiRoutingTests
{
    [Theory]
    [InlineData("/management/")]
    [InlineData("/management/users")]
    [InlineData("/management/users/user-1/edit")]
    [InlineData("/management/users/user-1/actions/mfa")]
    [InlineData("/management/users/user-1/actions/access")]
    [InlineData("/management/users/user-1/actions/password")]
    [InlineData("/management/users/user-1/actions/delete")]
    public async Task Authenticated_pages_render_with_overlapping_recovery_state_queries(string path)
    {
        var databasePath = Path.Combine(Path.GetTempPath(), $"identity-ui-authz-{Guid.NewGuid():N}.db");
        var reads = new DelayedRecoveryReads();
        try
        {
            await using var app = await CreateHostAsync(configureServices: services =>
                services.AddDbContext<AppDbContext>(options => options
                    .UseSqlite($"Data Source={databasePath};Pooling=False")
                    .UseOpenIddict().AddInterceptors(reads)));
            await using (var scope = app.Services.CreateAsyncScope())
                await scope.ServiceProvider.GetRequiredService<AppDbContext>().Database.EnsureCreatedAsync();

            using var client = app.GetTestClient();
            await SignInAsync(client, "administrator");
            using var response = await client.GetAsync(path);
            Assert.Equal(HttpStatusCode.OK, response.StatusCode);
            Assert.Contains("Clientes", WebUtility.HtmlDecode(await response.Content.ReadAsStringAsync()));
            Assert.True(reads.Queries > 1, "The real recovery-state queries must run during menu rendering.");
        }
        finally { File.Delete(databasePath); }
    }

    [Fact]
    public async Task Concurrent_policy_evaluations_use_independent_database_operations()
    {
        var databasePath = Path.Combine(Path.GetTempPath(), $"identity-ui-authz-{Guid.NewGuid():N}.db");
        var reads = new DelayedRecoveryReads(holdFirst: true);
        try
        {
            await using var app = await CreateHostAsync(configureServices: services =>
                services.AddDbContext<AppDbContext>(options => options
                    .UseSqlite($"Data Source={databasePath};Pooling=False")
                    .UseOpenIddict().AddInterceptors(reads)));
            await using var circuit = app.Services.CreateAsyncScope();
            await circuit.ServiceProvider.GetRequiredService<AppDbContext>().Database.EnsureCreatedAsync();
            var authorization = circuit.ServiceProvider.GetRequiredService<IAuthorizationService>();
            var principal = new ClaimsPrincipal(new ClaimsIdentity([
                new Claim(ClaimTypes.NameIdentifier, "operator-administrator"),
                new Claim(ClaimTypes.Role, "administrator"),
            ], "test"));
            var first = authorization.AuthorizeAsync(principal, null, ManagementUiPolicies.ManageClients);
            try
            {
                await reads.Entered.Task.WaitAsync(TimeSpan.FromSeconds(10));
                var results = await Task.WhenAll(Enumerable.Range(0, 12).Select(_ => Task.Run(() =>
                    authorization.AuthorizeAsync(principal, null, ManagementUiPolicies.ManageClients))));
                Assert.All(results, result => Assert.True(result.Succeeded));
            }
            finally
            {
                reads.Continue.TrySetResult();
                Assert.True((await first).Succeeded);
            }
        }
        finally { File.Delete(databasePath); }
    }

    [Fact]
    public async Task Same_authorization_service_observes_recovery_state_changes_without_caching_grants()
    {
        var databasePath = Path.Combine(Path.GetTempPath(), $"identity-ui-authz-{Guid.NewGuid():N}.db");
        try
        {
            await using var app = await CreateHostAsync(configureServices: services =>
                services.AddDbContext<AppDbContext>(options => options
                    .UseSqlite($"Data Source={databasePath};Pooling=False")
                    .UseOpenIddict().AddInterceptors(new RecoverySqliteFunctions())));
            const string subject = "recovery-operator";
            await using (var setup = app.Services.CreateAsyncScope())
            {
                var database = setup.ServiceProvider.GetRequiredService<AppDbContext>();
                await database.Database.EnsureCreatedAsync();
                database.Users.Add(new ApplicationUser
                {
                    Id = subject, UserName = subject,
                    Timestamp = DateTime.UtcNow, CreatedAtUtc = DateTime.UtcNow,
                });
                await database.SaveChangesAsync();
            }
            var principal = new ClaimsPrincipal(new ClaimsIdentity([
                new Claim(ClaimTypes.NameIdentifier, subject),
                new Claim(ClaimTypes.Role, "administrator"),
                new Claim("amr", "mfa"),
            ], "test"));
            await using var circuit = app.Services.CreateAsyncScope();
            var authorization = circuit.ServiceProvider.GetRequiredService<IAuthorizationService>();
            Assert.True((await authorization.AuthorizeAsync(principal, null, ManagementUiPolicies.ManageClients)).Succeeded);
            await using (var mutation = app.Services.CreateAsyncScope())
            {
                var database = mutation.ServiceProvider.GetRequiredService<AppDbContext>();
                database.UserTokens.Add(new IdentityUserToken<string>
                {
                    UserId = subject, LoginProvider = MfaRecoveryState.Provider,
                    Name = MfaRecoveryState.TokenName, Value = "required",
                });
                await database.SaveChangesAsync();
            }
            Assert.False((await authorization.AuthorizeAsync(principal, null, ManagementUiPolicies.ManageClients)).Succeeded);
        }
        finally { File.Delete(databasePath); }
    }

    private sealed class DelayedRecoveryReads(bool holdFirst = false) : DbCommandInterceptor
    {
        private int queries;
        public int Queries => Volatile.Read(ref queries);
        public TaskCompletionSource Entered { get; } = new(TaskCreationOptions.RunContinuationsAsynchronously);
        public TaskCompletionSource Continue { get; } = new(TaskCreationOptions.RunContinuationsAsynchronously);

        public override async ValueTask<InterceptionResult<DbDataReader>> ReaderExecutingAsync(
            DbCommand command, CommandEventData eventData,
            InterceptionResult<DbDataReader> result, CancellationToken cancellationToken = default)
        {
            if (command.CommandText.Contains("usertokens", StringComparison.OrdinalIgnoreCase))
            {
                var number = Interlocked.Increment(ref queries);
                if (holdFirst && number == 1)
                {
                    // Hold an active read until the other checks finish. No
                    // timing assumption: overlap is controlled by signals.
                    Entered.TrySetResult();
                    await Continue.Task.WaitAsync(cancellationToken);
                }
                else await Task.Yield();
            }
            return result;
        }
    }

    private sealed class RecoverySqliteFunctions : DbConnectionInterceptor
    {
        public override void ConnectionOpened(DbConnection connection, ConnectionEndEventData eventData)
        {
            var sqlite = (SqliteConnection)connection;
            sqlite.CreateFunction("UTC_TIMESTAMP", () => DateTime.UtcNow);
            sqlite.CreateFunction<int, DateTime>("UTC_TIMESTAMP", _ => DateTime.UtcNow);
        }

        public override Task ConnectionOpenedAsync(DbConnection connection,
            ConnectionEndEventData eventData, CancellationToken cancellationToken = default)
        {
            ConnectionOpened(connection, eventData);
            return Task.CompletedTask;
        }
    }
}
