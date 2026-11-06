using System.Net;
using System.Net.Sockets;

namespace Sufficit.Identity.Tests.Infrastructure;

/// <summary>
/// Owned loopback TCP relay for integration tests. Cut closes established sockets
/// and refuses new ones until Restore; it does not simulate silent packet loss.
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
            var toClient = outgoing.CopyToAsync(incoming, shutdown.Token);
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
