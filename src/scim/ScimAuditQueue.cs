using System.Threading.Channels;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using Sufficit.Identity.Core.Data;
using Sufficit.Identity.Core.Entities;

namespace Sufficit.Identity.Scim;

/// <summary>
/// Deferred sink for SCIM READ audit rows.
/// </summary>
/// <remarks>
/// Every SCIM read used to persist an audit row and call
/// <c>SaveChangesAsync</c> inline, so a GET turned into a write and a listing
/// paid for that write before it could answer. An authenticated provisioning
/// client polling reads could therefore amplify a read-only workload into
/// sustained write load against the identity database.
/// <para>
/// Reads are observability, not evidence: the record is worth keeping (SCIM
/// exposes the whole directory, so bulk reads are the exfiltration shape worth
/// noticing) but it does not have to be atomic with the response. MUTATIONS
/// keep their in-transaction audit precisely because there the atomicity is
/// the point — a privileged change must not be able to commit without its
/// record.
/// </para>
/// <para>
/// The queue is bounded. When it is saturated the entry is dropped rather
/// than growing memory without limit or blocking the request, and every drop
/// is counted and reported on shutdown — an audit trail that silently
/// truncates would read as complete when it is not.
/// </para>
/// </remarks>
internal interface IScimAuditQueue
{
    void Enqueue(ManagementAuditEvent auditEvent);
}

internal sealed class ScimAuditQueue : IScimAuditQueue
{
    // Deep enough to absorb a burst of listings, small enough that a stalled
    // writer cannot accumulate unbounded memory.
    private const int Capacity = 1024;

    // FullMode.Wait is what makes TryWrite report saturation instead of
    // silently discarding for us: the Drop* modes return true and drop an
    // entry internally, which would make an accurate drop count impossible.
    // TryWrite never blocks, so the request path is unaffected either way.
    private readonly Channel<ManagementAuditEvent> _channel =
        Channel.CreateBounded<ManagementAuditEvent>(
            new BoundedChannelOptions(Capacity)
            {
                FullMode = BoundedChannelFullMode.Wait,
                SingleReader = true,
            });

    private long _dropped;
    private long _accepted;
    private long _persisted;

    // Substituída a cada lote gravado. Quem quer esperar a gravação lê a
    // propriedade ANTES de provocar o trabalho e aguarda a Task capturada —
    // ler depois perderia o sinal de um lote que já passou.
    private TaskCompletionSource _flushed =
        new(TaskCreationOptions.RunContinuationsAsynchronously);

    public ChannelReader<ManagementAuditEvent> Reader => _channel.Reader;

    public long Dropped => Interlocked.Read(ref _dropped);

    public long Accepted => Interlocked.Read(ref _accepted);

    public long Persisted => Interlocked.Read(ref _persisted);

    /// <summary>
    /// Entradas aceitas que ainda não chegaram à tabela.
    /// </summary>
    /// <remarks>
    /// Até aqui o único sinal era a contagem de descartes, e ela só era
    /// relatada no desligamento. Uma fila que atrasa sem saturar não produzia
    /// sinal nenhum: o rastro de leitura ficava incompleto e nada dizia isso.
    /// </remarks>
    public long Backlog => Accepted - Persisted;

    /// <summary>
    /// Completa na próxima gravação bem-sucedida de um lote.
    /// </summary>
    public Task Flushed => Volatile.Read(ref _flushed).Task;

    public void Enqueue(ManagementAuditEvent auditEvent)
    {
        if (_channel.Writer.TryWrite(auditEvent))
        {
            Interlocked.Increment(ref _accepted);
        }
        else
        {
            Interlocked.Increment(ref _dropped);
        }
    }

    internal void MarkPersisted(int count)
    {
        Interlocked.Add(ref _persisted, count);

        // Troca o gatilho antes de disparar o antigo, para que quem for
        // aguardar o PRÓXIMO lote não receba o sinal deste.
        Interlocked
            .Exchange(
                ref _flushed,
                new TaskCompletionSource(
                    TaskCreationOptions.RunContinuationsAsynchronously))
            .SetResult();
    }
}

/// <summary>
/// Drains <see cref="ScimAuditQueue"/> into the audit table on a background
/// loop, batching whatever is already queued into a single round-trip.
/// </summary>
internal sealed class ScimAuditWorker(
    ScimAuditQueue queue,
    IDbContextFactory<AppDbContext> databaseFactory,
    ILogger<ScimAuditWorker> logger) : BackgroundService
{
    private const int MaximumBatchSize = 200;

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        while (await queue.Reader.WaitToReadAsync(stoppingToken))
        {
            var batch = new List<ManagementAuditEvent>(MaximumBatchSize);
            while (batch.Count < MaximumBatchSize
                && queue.Reader.TryRead(out var auditEvent))
            {
                batch.Add(auditEvent);
            }

            if (batch.Count == 0)
            {
                continue;
            }

            try
            {
                await using var database =
                    await databaseFactory.CreateDbContextAsync(stoppingToken);
                database.ManagementAuditEvents.AddRange(batch);
                await database.SaveChangesAsync(stoppingToken);
                queue.MarkPersisted(batch.Count);
            }
            catch (OperationCanceledException) when (stoppingToken.IsCancellationRequested)
            {
                throw;
            }
            catch (Exception error)
            {
                // A lost read-audit row must never take down the host, but it
                // must not vanish quietly either.
                logger.LogError(
                    error,
                    "Failed to persist {Count} SCIM read audit entries.",
                    batch.Count);
            }
        }
    }

    public override async Task StopAsync(CancellationToken cancellationToken)
    {
        await base.StopAsync(cancellationToken);

        if (queue.Dropped > 0)
        {
            logger.LogWarning(
                "{Dropped} SCIM read audit entries were dropped because the "
                + "queue was saturated; the read trail is incomplete.",
                queue.Dropped);
        }

        // Saturação não é a única forma de perder o rastro: o que ficou na fila
        // no desligamento também não chegou à tabela.
        if (queue.Backlog > 0)
        {
            logger.LogWarning(
                "{Backlog} SCIM read audit entries were still queued at "
                + "shutdown; the read trail is incomplete.",
                queue.Backlog);
        }
    }
}
