using System.Data;
using System.Data.Common;
using System.Diagnostics.CodeAnalysis;
using Sufficit.Identity.STS;
using Sufficit.Identity.STS.Diagnostics;
using Xunit;

namespace Sufficit.Identity.Tests;

public sealed class DatabaseCausalReadInterceptorTests
{
    [Fact]
    public void Compatibility_default_does_not_require_galera() => Assert.False(new DatabaseOptions().RequireGaleraCausalReads);

    [Theory]
    [InlineData(true)]
    [InlineData(false)]
    public async Task Unsupported_session_is_rejected_and_command_is_disposed(bool asynchronous)
    {
        using var connection = new ProbeConnection();
        connection.Command.Result = 0;
        var interceptor = new DatabaseCausalReadInterceptor();
        if (asynchronous)
            await Assert.ThrowsAsync<InvalidOperationException>(() => interceptor.ConnectionOpenedAsync(connection, null!));
        else
            Assert.Throws<InvalidOperationException>(() => interceptor.ConnectionOpened(connection, null!));
        Assert.True(connection.Command.WasDisposed);
    }

    [Theory]
    [InlineData(true)]
    [InlineData(false)]
    public async Task Setup_failure_is_not_swallowed(bool asynchronous)
    {
        using var connection = new ProbeConnection();
        var failure = new InvalidOperationException("probe failure");
        connection.Command.Failure = failure;
        var interceptor = new DatabaseCausalReadInterceptor();
        var observed = asynchronous
            ? await Record.ExceptionAsync(() => interceptor.ConnectionOpenedAsync(connection, null!))
            : Record.Exception(() => interceptor.ConnectionOpened(connection, null!));
        Assert.Same(failure, observed);
        Assert.True(connection.Command.WasDisposed);
    }

    [Fact]
    public async Task Cancellation_during_setup_reaches_command_and_is_propagated()
    {
        using var connection = new ProbeConnection();
        using var cancellation = new CancellationTokenSource();
        connection.Command.CancellationToTrigger = cancellation;
        await Assert.ThrowsAnyAsync<OperationCanceledException>(() =>
            new DatabaseCausalReadInterceptor().ConnectionOpenedAsync(connection, null!, cancellation.Token));
        Assert.Equal(cancellation.Token, connection.Command.ObservedToken);
        Assert.True(connection.Command.WasDisposed);
    }

    [Fact]
    public async Task Already_canceled_setup_does_not_create_a_command()
    {
        using var connection = new ProbeConnection();
        using var cancellation = new CancellationTokenSource();
        cancellation.Cancel();
        await Assert.ThrowsAnyAsync<OperationCanceledException>(() =>
            new DatabaseCausalReadInterceptor().ConnectionOpenedAsync(connection, null!, cancellation.Token));
        Assert.Equal(0, connection.Created);
    }

    private sealed class ProbeConnection : DbConnection
    {
        public ProbeCommand Command { get; } = new();
        public int Created { get; private set; }
        [AllowNull] public override string ConnectionString { get; set; } = "";
        public override string Database => "probe";
        public override string DataSource => "probe";
        public override string ServerVersion => "probe";
        public override ConnectionState State => ConnectionState.Open;
        public override void ChangeDatabase(string databaseName) => throw new NotSupportedException();
        public override void Close() { }
        public override void Open() { }
        protected override DbTransaction BeginDbTransaction(IsolationLevel isolationLevel) => throw new NotSupportedException();
        protected override DbCommand CreateDbCommand() { Created++; return Command; }
    }

    private sealed class ProbeCommand : DbCommand
    {
        public object Result { get; set; } = 1;
        public Exception? Failure { get; set; }
        public CancellationTokenSource? CancellationToTrigger { get; set; }
        public CancellationToken ObservedToken { get; private set; }
        public bool WasDisposed { get; private set; }
        [AllowNull] public override string CommandText { get; set; } = "";
        public override int CommandTimeout { get; set; }
        public override CommandType CommandType { get; set; }
        public override bool DesignTimeVisible { get; set; }
        public override UpdateRowSource UpdatedRowSource { get; set; }
        protected override DbConnection? DbConnection { get; set; }
        protected override DbTransaction? DbTransaction { get; set; }
        protected override DbParameterCollection DbParameterCollection => throw new NotSupportedException();
        public override void Cancel() { }
        public override int ExecuteNonQuery() => throw new NotSupportedException();
        public override object ExecuteScalar() => Failure is { } failure ? throw failure : Result;
        public override Task<object?> ExecuteScalarAsync(CancellationToken cancellationToken)
        {
            ObservedToken = cancellationToken;
            CancellationToTrigger?.Cancel();
            cancellationToken.ThrowIfCancellationRequested();
            return Task.FromResult<object?>(ExecuteScalar());
        }
        public override void Prepare() => throw new NotSupportedException();
        protected override DbParameter CreateDbParameter() => throw new NotSupportedException();
        protected override DbDataReader ExecuteDbDataReader(CommandBehavior behavior) => throw new NotSupportedException();
        protected override void Dispose(bool disposing) { WasDisposed = true; base.Dispose(disposing); }
    }
}
