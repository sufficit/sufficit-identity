using System.Net;
using System.Net.Sockets;

namespace Sufficit.Identity.Tests.Infrastructure;

/// <summary>
/// Owned loopback TCP relay for integration tests. Cut closes established sockets
/// and refuses new ones until Restore. Optional server-to-client discard keeps
/// TCP open and signals when the requested test marker has actually been dropped.
/// </summary>
internal sealed class InterruptibleTcpRelay : IAsyncDisposable
{
    private readonly TcpListener listener = new(IPAddress.Loopback, 0);
    private readonly CancellationTokenSource shutdown = new();
    private readonly object gate = new();
    private readonly List<(TcpClient Client, TcpClient Server)> connections = [];
    private readonly List<Task> relays = [];
    private readonly string host;
    private readonly int port;
    private readonly Task accepting;
    private bool cut;
    private DiscardState? discard;

    public InterruptibleTcpRelay(Uri target)
    {
        if (!target.IsLoopback) throw new ArgumentException("Only loopback targets are supported.", nameof(target));
        host = target.Host;
        port = target.Port;
        listener.Start();
        Port = ((IPEndPoint)listener.LocalEndpoint).Port;
        accepting = AcceptAsync();
    }

    public int Port { get; }

    public Task DropServerTraffic(string marker)
    {
        var state = new DiscardState(marker);
        Volatile.Write(ref discard, state);
        return state.Observed.Task;
    }

    public void ResumeServerTraffic() => Volatile.Write(ref discard, null);

    private sealed class DiscardState(string marker)
    {
        private string seen = string.Empty;
        public TaskCompletionSource Observed { get; } = new(TaskCreationOptions.RunContinuationsAsynchronously);
        public void Observe(ReadOnlySpan<byte> bytes)
        {
            lock (this)
            {
                seen += System.Text.Encoding.UTF8.GetString(bytes);
                if (seen.Contains(marker, StringComparison.Ordinal)) Observed.TrySetResult();
                // Retain only enough suffix to detect a marker split across reads.
                if (seen.Length > marker.Length) seen = seen[^marker.Length..];
            }
        }
    }

    private async Task ForwardServerAsync(Stream source, Stream destination)
    {
        var buffer = new byte[8192];
        int count;
        while ((count = await source.ReadAsync(buffer, shutdown.Token)) != 0)
        {
            if (Volatile.Read(ref discard) is { } state)
                state.Observe(buffer.AsSpan(0, count));
            else
                await destination.WriteAsync(buffer.AsMemory(0, count), shutdown.Token);
        }
    }

    public void Cut()
    {
        lock (gate)
        {
            cut = true;
            foreach (var (client, server) in connections)
            {
                client.Dispose();
                server.Dispose();
            }
        }
    }

    public void Restore()
    {
        lock (gate) cut = false;
    }

    private async Task AcceptAsync()
    {
        try
        {
            while (!shutdown.IsCancellationRequested)
            {
                var client = await listener.AcceptTcpClientAsync(shutdown.Token);
                lock (gate)
                {
                    if (cut)
                    {
                        client.Dispose();
                        continue;
                    }
                    var server = new TcpClient();
                    connections.Add((client, server));
                    relays.Add(RelayAsync(client, server));
                }
            }
        }
        catch (OperationCanceledException) when (shutdown.IsCancellationRequested) { }
    }

    private async Task RelayAsync(TcpClient client, TcpClient server)
    {
        try
        {
            await server.ConnectAsync(host, port, shutdown.Token);
            var incoming = client.GetStream();
            var outgoing = server.GetStream();
            var toServer = incoming.CopyToAsync(outgoing, shutdown.Token);
            var toClient = ForwardServerAsync(outgoing, incoming);
            await Task.WhenAny(toServer, toClient);
            client.Dispose();
            server.Dispose();
            await Task.WhenAll(toServer, toClient);
        }
        catch (IOException) { } // Peer close and explicit fault injection.
        catch (SocketException) { }
        catch (ObjectDisposedException) { }
        catch (OperationCanceledException) when (shutdown.IsCancellationRequested) { }
        finally
        {
            client.Dispose();
            server.Dispose();
            lock (gate) connections.Remove((client, server));
        }
    }

    public async ValueTask DisposeAsync()
    {
        shutdown.Cancel();
        Cut();
        await accepting;
        listener.Stop();
        await Task.WhenAll(relays);
        shutdown.Dispose();
    }
}
