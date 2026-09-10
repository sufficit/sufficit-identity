using System.Threading.Channels;

namespace Sufficit.Identity.Server;

/// <summary>Bounded invalidation mailbox: at most one queued and one executing refresh.</summary>
internal sealed class TrustedProxyRefreshSignal
{
    private readonly Channel<string> channel = Channel.CreateBounded<string>(new BoundedChannelOptions(1)
    { FullMode = BoundedChannelFullMode.DropOldest, SingleReader = true, SingleWriter = false });
    public ChannelReader<string> Reader => channel.Reader;
    public void Request(string? revision = null) => channel.Writer.TryWrite(revision ?? string.Empty);
}
