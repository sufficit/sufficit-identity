using System.Security.Claims;
using Microsoft.Data.Sqlite;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging.Abstractions;
using Sufficit.Identity.Core.Data;
using Sufficit.Identity.Management;
using Sufficit.Identity.Management.Audit;
using Sufficit.Identity.Management.Authorization;
using Xunit;

namespace Sufficit.Identity.Tests;

public sealed class ManagementOperationExecutorTests
{
    private static readonly ManagementRequestContext Context = new(
        new ClaimsPrincipal(new ClaimsIdentity([new Claim("sub", "operator-example")], "test")),
        "executor-test");
    private static readonly ManagementResource Resource = new(ManagementResourceTypes.Client, "example-client");

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task Denial_auditing_is_explicit_and_does_not_suppress_repeated_refusals(bool audit)
    {
        using var connection = new SqliteConnection("Data Source=:memory:");
        await connection.OpenAsync();
        await using var database = CreateDatabase(connection);
        await database.Database.EnsureCreatedAsync();
        var decision = ManagementAuthorizationDecision.Denied("example_denial");
        var executor = CreateExecutor(database, decision);
        for (var i = 0; i < 2; i++)
        {
            await Assert.ThrowsAsync<ManagementAccessException>(() => executor.DemandAsync(
                Context, ManagementCapabilities.ClientsUpdate, Resource, default, audit));
        }
        var rows = await database.ManagementAuditEvents.ToArrayAsync();
        Assert.Equal(audit ? 2 : 0, rows.Length);
        Assert.All(rows, row =>
        {
            Assert.Equal("denied", row.OperationOutcome);
            Assert.Equal("example_denial", row.ReasonCode);
            Assert.Equal(Resource.Id, row.ResourceId);
        });
    }

    [Fact]
    public async Task Successful_demand_does_not_save_or_require_an_audit_table()
    {
        using var connection = new SqliteConnection("Data Source=:memory:");
        await connection.OpenAsync();
        await using var database = CreateDatabase(connection); // Deliberately no schema.
        var decision = ManagementAuthorizationDecision.Allowed();
        Assert.Same(decision, await CreateExecutor(database, decision).DemandAsync(
            Context, ManagementCapabilities.ClientsUpdate, Resource, default, auditDenial: true));
        Assert.Empty(database.ChangeTracker.Entries());
    }

    [Fact]
    public async Task Audit_storage_failure_does_not_replace_the_denial()
    {
        using var connection = new SqliteConnection("Data Source=:memory:");
        await connection.OpenAsync();
        await using var database = CreateDatabase(connection); // Missing audit table forces save failure.
        await Assert.ThrowsAsync<ManagementAccessException>(() =>
            CreateExecutor(database, ManagementAuthorizationDecision.Denied("original_denial"))
                .DemandAsync(Context, ManagementCapabilities.ClientsUpdate, Resource, default, true));
    }

    [Fact]
    public async Task Outcome_audit_participates_in_the_callers_transaction()
    {
        using var connection = new SqliteConnection("Data Source=:memory:");
        await connection.OpenAsync();
        await using var database = CreateDatabase(connection);
        await database.Database.EnsureCreatedAsync();
        var decision = ManagementAuthorizationDecision.Allowed();
        await using (var transaction = await database.Database.BeginTransactionAsync())
        {
            await CreateExecutor(database, decision).TryWriteAuditAsync(Context,
                ManagementCapabilities.ClientsUpdate, Resource, decision, "failed", "example_failure", default);
            Assert.Equal(1, await database.ManagementAuditEvents.CountAsync());
            await transaction.RollbackAsync();
        }
        Assert.Equal(0, await database.ManagementAuditEvents.CountAsync());
    }

    [Fact]
    public async Task Authorization_cancellation_propagates_without_creating_an_audit_row()
    {
        using var connection = new SqliteConnection("Data Source=:memory:");
        await connection.OpenAsync();
        await using var database = CreateDatabase(connection);
        using var cancellation = new CancellationTokenSource();
        cancellation.Cancel();
        await Assert.ThrowsAnyAsync<OperationCanceledException>(() =>
            CreateExecutor(database, ManagementAuthorizationDecision.Allowed()).DemandAsync(
                Context, ManagementCapabilities.ClientsUpdate, Resource, cancellation.Token, true));
        Assert.Empty(database.ChangeTracker.Entries());
    }

    private static AppDbContext CreateDatabase(SqliteConnection connection) =>
        new(new DbContextOptionsBuilder<AppDbContext>().UseSqlite(connection).UseOpenIddict().Options);

    private static ManagementOperationExecutor CreateExecutor(AppDbContext database, ManagementAuthorizationDecision decision) =>
        new(new Evaluator(decision), database, NullLogger<ManagementOperationExecutor>.Instance);

    private sealed class Evaluator(ManagementAuthorizationDecision decision) : IManagementAuthorizationEvaluator
    {
        public ValueTask<ManagementAuthorizationDecision> EvaluateAsync(ClaimsPrincipal principal,
            string capability, ManagementResource resource, CancellationToken cancellationToken = default)
        {
            cancellationToken.ThrowIfCancellationRequested();
            return ValueTask.FromResult(decision);
        }
    }
}
